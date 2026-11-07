//! The window frame the app draws itself where the system draws none.
//!
//! On a Wayland desktop that leaves window frames to the applications, such
//! as GNOME, winit draws a frame of its own that rounds only its title bar.
//! There the app turns that frame off and draws a title bar and rounded
//! corners itself (`own-frame` in `ui/app.slint`). Everywhere else the system
//! frame stays.
//!
//! The choice is made twice. Before the window exists, the compositor is
//! asked whether it draws frames, so the window shows with the right frame
//! from the start. Once the window exists, what the system did is read back
//! from it, and the choice is corrected where the two differ.

use crate::AppWindow;
use slint::platform::WindowEvent;
use slint::winit_030::WinitWindowAccessor;
use slint::winit_030::winit::dpi::LogicalPosition;
use slint::winit_030::winit::raw_window_handle::{HasDisplayHandle, RawDisplayHandle};
use slint::{ComponentHandle, SetRenderingNotifierError, Timer};
use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry::{self, WlRegistry};
use wayland_client::{Connection, Dispatch, QueueHandle};

/// The Wayland global through which a compositor offers to draw window
/// frames itself.
const DECORATION_MANAGER: &str = "zxdg_decoration_manager_v1";

/// Files whose presence tells Slint's winit backend that it runs under WSL,
/// where it uses X11 even when a Wayland display is available.
const WSL_MARKERS: [&str; 2] = ["/proc/sys/fs/binfmt_misc/WSLInterop", "/run/WSL"];

/// Gives the window the frame it needs: the app's own where the system
/// draws none, the system's everywhere else.
pub(crate) fn install(app: &AppWindow) {
    wire(app);
    app.set_own_frame(system_draws_no_frame());
    settle_once_shown(app);
}

/// Whether the system leaves this window without a frame, so the app draws
/// its own.
///
/// winit runs on Wayland when `WAYLAND_DISPLAY` names a compositor, except
/// under WSL. It asks the compositor to draw the frame, and only a compositor
/// that offers `zxdg_decoration_manager_v1` can. GNOME offers none. This asks
/// the same compositor through a connection of its own, opened by the
/// socket's path so that a `WAYLAND_SOCKET` handed to winit is never taken.
/// Any failure answers `false`, which keeps the system's frame. Unless winit
/// was handed a connection in `WAYLAND_SOCKET`, it uses the compositor that
/// `WAYLAND_DISPLAY` names, and `AppWindow::new` has already connected it,
/// so the one roundtrip here cannot block where winit's did not.
fn system_draws_no_frame() -> bool {
    struct Registry;
    impl Dispatch<WlRegistry, GlobalListContents> for Registry {
        fn event(
            _: &mut Self,
            _: &WlRegistry,
            _: wl_registry::Event,
            _: &GlobalListContents,
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
        }
    }

    if WSL_MARKERS.iter().any(|marker| Path::new(marker).exists()) {
        return false;
    }
    let Some(socket) = wayland_socket_path(
        std::env::var_os("WAYLAND_DISPLAY"),
        std::env::var_os("XDG_RUNTIME_DIR"),
    ) else {
        return false;
    };
    let Ok(stream) = UnixStream::connect(socket) else {
        return false;
    };
    let Ok(connection) = Connection::from_socket(stream) else {
        return false;
    };
    let Ok((globals, _queue)) = registry_queue_init::<Registry>(&connection) else {
        return false;
    };
    !globals.contents().with_list(|list| {
        list.iter()
            .any(|global| global.interface == DECORATION_MANAGER)
    })
}

/// The socket of the compositor that `WAYLAND_DISPLAY` names, resolved as
/// libwayland resolves it: an absolute path as it is, a name inside
/// `XDG_RUNTIME_DIR`. `None` when either needed value is missing or empty.
fn wayland_socket_path(
    display: Option<OsString>,
    runtime_dir: Option<OsString>,
) -> Option<PathBuf> {
    let display = PathBuf::from(display.filter(|value| !value.is_empty())?);
    if display.is_absolute() {
        return Some(display);
    }
    let runtime_dir = PathBuf::from(runtime_dir.filter(|value| !value.is_empty())?);
    Some(runtime_dir.join(display))
}

/// Corrects the frame chosen before the window existed, once the window
/// shows what the system did.
///
/// The app's own frame stays only on Wayland, and only with a renderer that
/// draws transparent pixels: Slint's software renderer, its fallback when
/// OpenGL is unavailable, has no alpha channel on Wayland and would show the
/// rounded corners black. It is told apart as the one renderer that does
/// not support rendering notifiers. The notifier set here does nothing, but
/// it takes the window's one notifier slot, so any later notifier on these
/// systems has to replace this check.
///
/// The app's own frame also replaces the one winit draws when the
/// compositor offers to draw frames but leaves this window's to winit:
/// winit's frame then makes the window's outer height larger than its inner.
/// winit hands over a Wayland window only after the compositor's first
/// configure, which settles who draws the frame, so that height is already
/// final here.
fn settle_once_shown(app: &AppWindow) {
    let weak = app.as_weak();
    // Fails only without a Slint backend, and `AppWindow::new` selected one.
    let _ = slint::spawn_local(async move {
        let Some(app) = weak.upgrade() else { return };
        let Ok(window) = app.window().winit_window().await else {
            return;
        };
        let wayland = window
            .display_handle()
            .is_ok_and(|display| matches!(display.as_raw(), RawDisplayHandle::Wayland(_)));
        let transparent = wayland
            && !matches!(
                app.window().set_rendering_notifier(|_, _| {}),
                Err(SetRenderingNotifierError::Unsupported)
            );
        let winit_frame = window.outer_size().height > window.inner_size().height;
        app.set_own_frame(wayland && transparent && (app.get_own_frame() || winit_frame));
    });
}

/// Connects the title bar the app draws to the window it moves, minimizes,
/// and closes.
pub(crate) fn wire(app: &AppWindow) {
    app.on_move_window({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            // A compositor that refuses the move leaves the window where it is.
            app.window().with_winit_window(|window| {
                let _ = window.drag_window();
            });
            // The compositor now holds the pointer and keeps the release of
            // the press that started the move, so Slint would go on treating
            // the button as held and give the next press to the title bar,
            // which would move the window again. Telling Slint the pointer
            // left ends that, once it has finished with the press.
            let weak = app.as_weak();
            Timer::single_shot(Duration::ZERO, move || {
                if let Some(app) = weak.upgrade() {
                    app.window().dispatch_event(WindowEvent::PointerExited);
                }
            });
        }
    });
    app.on_show_window_menu({
        let weak = app.as_weak();
        move |x, y| {
            if let Some(app) = weak.upgrade() {
                app.window().with_winit_window(|window| {
                    window.show_window_menu(LogicalPosition::new(f64::from(x), f64::from(y)));
                });
            }
        }
    });
    app.on_minimize_window({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.window().set_minimized(true);
            }
        }
    });
    // The same request the system's close button sends.
    app.on_close_window({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.window().dispatch_event(WindowEvent::CloseRequested);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> Option<OsString> {
        Some(OsString::from(value))
    }

    #[test]
    fn a_display_name_resolves_inside_the_runtime_directory() {
        assert_eq!(
            wayland_socket_path(path("wayland-0"), path("/run/user/1000")),
            Some(PathBuf::from("/run/user/1000/wayland-0"))
        );
    }

    #[test]
    fn an_absolute_display_path_is_used_as_it_is() {
        assert_eq!(
            wayland_socket_path(path("/tmp/compositor"), None),
            Some(PathBuf::from("/tmp/compositor"))
        );
    }

    #[test]
    fn a_missing_or_empty_value_names_no_socket() {
        assert_eq!(wayland_socket_path(None, path("/run/user/1000")), None);
        assert_eq!(wayland_socket_path(path(""), path("/run/user/1000")), None);
        assert_eq!(wayland_socket_path(path("wayland-0"), None), None);
        assert_eq!(wayland_socket_path(path("wayland-0"), path("")), None);
    }
}
