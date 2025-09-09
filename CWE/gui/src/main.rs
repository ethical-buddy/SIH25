use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Button, Box, ListBox, ListBoxRow, Label, Orientation, MessageDialog};
use cwe::device::{enumerate_block_devices_linux, DeviceType};


fn build_ui(app: &Application) {
    let window = ApplicationWindow::new(app);
    window.set_title(Some("Drive Purge Utility"));
    window.set_default_size(600, 400);

    let vbox = Box::new(Orientation::Vertical, 10);
    let listbox = ListBox::new();

    match enumerate_block_devices_linux("run") {
        Ok(devices) => {
            for dev in devices.iter() {
                let row = ListBoxRow::new();
                let hbox = Box::new(Orientation::Horizontal, 5);

                let label = Label::new(Some(&format!(
                    "{} ({}) [{:?}]",
                    dev.dev_path,
                    dev.model.clone().unwrap_or("Unknown".into()),
                    dev.devtype
                )));

                let button = Button::with_label("Crypto Purge (simulate)");
                let dev_path = dev.dev_path.clone();
                let parent = window.clone();

                button.connect_clicked(move |_| {
                    let msg = format!("Would purge {}", dev_path);
                    let dialog = MessageDialog::builder()
                        .transient_for(&parent)
                        .modal(true)
                        .message_type(gtk4::MessageType::Info)
                        .buttons(gtk4::ButtonsType::Ok)
                        .text(&msg)
                        .build();
                    dialog.connect_response(|d, _| d.close());
                    dialog.show();
                });

                hbox.append(&label);
                hbox.append(&button);
                row.set_child(Some(&hbox));
                listbox.append(&row);
            }
        }
        Err(e) => {
            let error_label = Label::new(Some(&format!("Error: {}", e)));
            vbox.append(&error_label);
        }
    }

    vbox.append(&listbox);
    window.set_child(Some(&vbox));
    window.show();
}

fn main() {
    let app = Application::builder()
        .application_id("com.example.purgeutil")
        .build();

    app.connect_activate(build_ui);
    app.run();
}
