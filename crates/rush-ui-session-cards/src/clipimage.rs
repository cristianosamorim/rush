//! An image on the clipboard into the message box, as ctrl+v does in
//! Claude Code: a terminal pastes only text, so a screenshot copied to the
//! clipboard never reaches rush as a paste. After Go's
//! internal/ui/clipimage.go (setClipboard :18, pasteClipImage :42,
//! clipImage :65, clipJXA :140).

use std::path::PathBuf;
use std::process::Command;

use super::{Act, act};
use crate::frame::Out;
#[cfg(target_os = "macos")]
use crate::frame::editor::is_image_file;
use crate::model::Model;

pub use crate::imagerefs::ClipState;

/// ctrl+v and cmd+v in a Session's box read an image off the clipboard: a
/// terminal that pastes only text lets them through when the clipboard
/// holds just an image (rushmode.go:3955; a session_keys hook, after the
/// cards').
pub fn clip_key_hook(m: &mut Model, k: &crate::frame::Press) -> Out {
    if k.s != "ctrl+v" && k.s != "super+v" {
        return Out::Pass;
    }
    match super::open_key(m) {
        Some(key) if super::info(m, &key).is_some() => paste_clip_image(m, &key),
        _ => Out::Pass,
    }
}

/// Reads an image off the clipboard off the UI thread, and attaches it to
/// agent key's box once it's back (pasteClipImage, clipImageMsg).
pub fn paste_clip_image(m: &mut Model, key: &str) -> Out {
    if m.kept::<ClipState>().pasting {
        return Out::Idle; // one read at a time
    }
    m.kept::<ClipState>().pasting = true;
    m.flash("reading the clipboard…");
    let key = key.to_string();
    m.later(clip_image, move |m, r| {
        m.kept::<ClipState>().pasting = false;
        match r {
            Err(e) => {
                m.fail(&format!("couldn't read the clipboard: {e}"));
                Out::Draw
            }
            Ok(None) => {
                m.flash("no image on the clipboard");
                Out::Draw
            }
            Ok(Some(p)) => act(m, &key, Act::AttachImages(vec![p])),
        }
    });
    Out::Draw
}

/// The image on the clipboard as a file: an image file copied in the
/// Finder as itself, image data saved as a PNG under the temp dir. None
/// when the clipboard holds no image.
pub fn clip_image() -> Result<Option<String>, String> {
    let dir = images_dir();
    #[cfg(target_os = "linux")]
    private_image_dir(&dir)?;
    #[cfg(not(target_os = "linux"))]
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out = dir.join(format!(
        "clipboard-{}.png",
        super::clock::stamp(rush_core::time::now())
    ));
    let outs = out.to_string_lossy().into_owned();
    #[cfg(target_os = "macos")]
    {
        // Asked of NSPasteboard directly: AppleScript's «the clipboard»
        // converts every format it holds first, seconds for a screenshot.
        let o = Command::new("osascript")
            .args(["-l", "JavaScript", "-e", CLIP_JXA, &outs])
            .output()
            .map_err(|e| e.to_string())?;
        if !o.status.success() {
            return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
        }
        let res = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Some(p) = res.strip_prefix("file:") {
            // A copied file: attach the file itself when it's an image.
            let ok = std::fs::metadata(p).is_ok_and(|m| !m.is_dir()) && is_image_file(p);
            return Ok(ok.then(|| p.to_string()));
        }
        if res.is_empty() {
            return Ok(None);
        }
    }
    #[cfg(target_os = "linux")]
    if !linux_clipboard(&out)? {
        return Ok(None);
    }
    if std::fs::metadata(&out).map_or(true, |m| m.len() == 0) {
        let _ = std::fs::remove_file(&out);
        return Ok(None);
    }
    Ok(Some(outs))
}

/// Linux desktops expose image data through their clipboard utilities.
/// Write straight to a private, newly created file rather than keeping
/// a potentially large image in the UI process's memory.
#[cfg(target_os = "linux")]
fn linux_clipboard(out: &std::path::Path) -> Result<bool, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut available = false;
    for (program, args) in [
        ("wl-paste", &["--no-newline", "--type", "image/png"][..]),
        (
            "xclip",
            &["-selection", "clipboard", "-target", "image/png", "-out"][..],
        ),
    ] {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)
            .map_err(|e| e.to_string())?;
        let result = Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(file)
            .stderr(std::process::Stdio::null())
            .status();
        if let Ok(status) = result {
            available = true;
            if status.success() && std::fs::metadata(out).is_ok_and(|m| m.len() > 0) {
                return Ok(true);
            }
        }
        let _ = std::fs::remove_file(out);
    }
    if available {
        Ok(false)
    } else {
        Err("image pasting needs wl-clipboard (Wayland) or xclip (X11)".into())
    }
}

/// Puts text on the clipboard through pbcopy as well as the terminal, on a
/// Mac rush runs on: Terminal.app ignores OSC 52 (setClipboard). Runs off
/// the UI thread; the terminal's copy is the frame's.
pub fn pbcopy(m: &mut Model, text: String) {
    if !cfg!(target_os = "macos") {
        return; // Linux terminals receive the existing OSC 52 copy.
    }
    if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
        return;
    }
    m.later(
        move || {
            use std::io::Write;
            if let Ok(mut c) = Command::new("pbcopy")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(mut i) = c.stdin.take() {
                    let _ = i.write_all(text.as_bytes());
                }
                let _ = c.wait();
            }
        },
        |_, ()| Out::Idle,
    );
}

/// The folder clipboard images are saved in.
pub fn images_dir() -> PathBuf {
    if cfg!(target_os = "linux") {
        return rush_state::dir().join("clipboard-images");
    }
    std::env::temp_dir().join("rush-images")
}

#[cfg(target_os = "linux")]
fn private_image_dir(dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| e.to_string())?;
    let metadata = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    // SAFETY: geteuid reads this process's effective user id.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(
            "the clipboard image directory must be a private directory owned by you".into(),
        );
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn image_directory_is_private_and_rejects_shared_or_substituted_paths() {
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join("images");
        private_image_dir(&private).unwrap();
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let link = temp.path().join("substituted");
        symlink(&private, &link).unwrap();
        assert!(private_image_dir(&link).is_err());
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_image_dir(&private).is_err());
    }
}

/// Writes the clipboard's image to argv[0] as a PNG and prints "png",
/// prints "file:" and the path of a copied file, or prints nothing.
pub const CLIP_JXA: &str = r#"ObjC.import('AppKit');
function run(argv) {
  const pb = $.NSPasteboard.generalPasteboard;
  const url = $.NSURL.URLFromPasteboard(pb);
  if (!url.isNil() && url.isFileURL) return 'file:' + url.path.js;
  let d = pb.dataForType('public.png');
  if (d.isNil()) {
    const tiff = pb.dataForType('public.tiff');
    if (tiff.isNil()) return '';
    d = $.NSBitmapImageRep.imageRepWithData(tiff).representationUsingTypeProperties($.NSBitmapImageFileTypePNG, $());
  }
  return d.writeToFileAtomically(argv[0], true) ? 'png' : '';
}"#;
