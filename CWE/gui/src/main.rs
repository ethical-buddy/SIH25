use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Button, Box, ListBox, ListBoxRow, Label, 
    Orientation, MessageDialog, HeaderBar, Stack, StackSidebar, Separator,
    ScrolledWindow, Frame, CheckButton, ProgressBar, ButtonsType, MessageType
};
use cwe::device::enumerate_block_devices_linux;
use std::rc::Rc;
use std::cell::RefCell;
use cwe::device::Device;

#[derive(Clone)]
struct AppState {
    window: ApplicationWindow,
    stack: Stack,
    selected_device: Rc<RefCell<Option<String>>>,
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::new(app);
    window.set_title(Some("Device Wiper"));
    window.set_default_size(800, 600);

    // Create header bar
    let header = HeaderBar::new();
    header.set_title_widget(Some(&Label::new(Some("Device Wiper"))));
    window.set_titlebar(Some(&header));

    // Create stack for navigation
    let stack = Stack::new();
    stack.set_transition_type(gtk4::StackTransitionType::SlideLeftRight);

    let app_state = AppState {
        window: window.clone(),
        stack: stack.clone(),
        selected_device: Rc::new(RefCell::new(None)),
    };

    // Build device selection page
    build_device_selection_page(&stack, &app_state);
    
    // Build wipe options page
    build_wipe_options_page(&stack, &app_state);

    window.set_child(Some(&stack));
    window.show();
}

fn build_device_selection_page(stack: &Stack, app_state: &AppState) {
    let main_box = Box::new(Orientation::Vertical, 0);
    
    // Title section
    let title_box = Box::new(Orientation::Vertical, 10);
    title_box.set_margin_top(30);
    title_box.set_margin_bottom(20);
    title_box.set_margin_start(20);
    title_box.set_margin_end(20);
    
    let title = Label::new(Some("Select Device to Wipe"));
    title.add_css_class("title-1");
    
    let subtitle = Label::new(Some("Choose a storage device from the list below"));
    subtitle.add_css_class("subtitle");
    subtitle.add_css_class("dim-label");
    
    title_box.append(&title);
    title_box.append(&subtitle);
    
    // Device list section
    let list_frame = Frame::new(None);
    list_frame.set_margin_start(20);
    list_frame.set_margin_end(20);
    list_frame.set_margin_bottom(20);
    
    let scrolled = ScrolledWindow::new();
    scrolled.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);
    scrolled.set_min_content_height(300);
    
    let listbox = ListBox::new();
    listbox.set_selection_mode(gtk4::SelectionMode::None);
    listbox.add_css_class("boxed-list");
    
    // Populate device list
    match enumerate_block_devices_linux("run") {
        Ok(devices) => {
            if devices.is_empty() {
                let empty_row = create_empty_state_row();
                listbox.append(&empty_row);
            } else {
                for dev in devices.iter() {
                    let row = create_device_row(dev, app_state);
                    listbox.append(&row);
                }
            }
        }
        Err(e) => {
            let error_row = create_error_row(&e.to_string());
            listbox.append(&error_row);
        }
    }
    
    scrolled.set_child(Some(&listbox));
    list_frame.set_child(Some(&scrolled));
    
    main_box.append(&title_box);
    main_box.append(&list_frame);
    
    stack.add_titled(&main_box, Some("devices"), "Select Device");
}

fn create_device_row(dev: &Device, app_state: &AppState) -> ListBoxRow {
    let row = ListBoxRow::new();
    row.set_activatable(false);
    
    let hbox = Box::new(Orientation::Horizontal, 15);
    hbox.set_margin_top(15);
    hbox.set_margin_bottom(15);
    hbox.set_margin_start(15);
    hbox.set_margin_end(15);
    
    // Device info section
    let info_box = Box::new(Orientation::Vertical, 5);
    info_box.set_hexpand(true);
    
    let device_name = Label::new(Some(&dev.dev_path));
    device_name.set_halign(gtk4::Align::Start);
    device_name.add_css_class("heading");
    
    let model_text = dev.model.clone().unwrap_or("Unknown Model".into());
    let device_info = Label::new(Some(&format!("{} • {:?}", model_text, dev.devtype)));
    device_info.set_halign(gtk4::Align::Start);
    device_info.add_css_class("dim-label");
    
    info_box.append(&device_name);
    info_box.append(&device_info);
    
    // Action button
    let select_button = Button::with_label("Select");
    select_button.add_css_class("suggested-action");
    select_button.set_valign(gtk4::Align::Center);
    
    let dev_path = dev.dev_path.clone();
    let app_state_clone = app_state.clone();
    select_button.connect_clicked(move |_| {
        *app_state_clone.selected_device.borrow_mut() = Some(dev_path.clone());
        app_state_clone.stack.set_visible_child_name("wipe-options");
    });
    
    hbox.append(&info_box);
    hbox.append(&select_button);
    row.set_child(Some(&hbox));
    
    row
}

fn create_empty_state_row() -> ListBoxRow {
    let row = ListBoxRow::new();
    row.set_activatable(false);
    
    let vbox = Box::new(Orientation::Vertical, 10);
    vbox.set_margin_top(40);
    vbox.set_margin_bottom(40);
    vbox.set_margin_start(20);
    vbox.set_margin_end(20);
    
    let icon_label = Label::new(Some("🔍"));
    icon_label.add_css_class("title-1");
    
    let message = Label::new(Some("No storage devices found"));
    message.add_css_class("title-4");
    
    let subtitle = Label::new(Some("Make sure devices are properly connected"));
    subtitle.add_css_class("dim-label");
    
    vbox.append(&icon_label);
    vbox.append(&message);
    vbox.append(&subtitle);
    vbox.set_halign(gtk4::Align::Center);
    
    row.set_child(Some(&vbox));
    row
}

fn create_error_row(error: &str) -> ListBoxRow {
    let row = ListBoxRow::new();
    row.set_activatable(false);
    
    let vbox = Box::new(Orientation::Vertical, 10);
    vbox.set_margin_top(40);
    vbox.set_margin_bottom(40);
    vbox.set_margin_start(20);
    vbox.set_margin_end(20);
    
    let icon_label = Label::new(Some("⚠️"));
    icon_label.add_css_class("title-1");
    
    let message = Label::new(Some("Error loading devices"));
    message.add_css_class("title-4");
    
    let error_label = Label::new(Some(error));
    error_label.add_css_class("dim-label");
    error_label.set_wrap(true);
    
    vbox.append(&icon_label);
    vbox.append(&message);
    vbox.append(&error_label);
    vbox.set_halign(gtk4::Align::Center);
    
    row.set_child(Some(&vbox));
    row
}

fn build_wipe_options_page(stack: &Stack, app_state: &AppState) {
    let main_box = Box::new(Orientation::Vertical, 0);
    
    // Header with back button
    let header_box = Box::new(Orientation::Horizontal, 10);
    header_box.set_margin_top(20);
    header_box.set_margin_bottom(20);
    header_box.set_margin_start(20);
    header_box.set_margin_end(20);
    
    let back_button = Button::with_label("← Back");
    let stack_clone = app_state.stack.clone();
    back_button.connect_clicked(move |_| {
        stack_clone.set_visible_child_name("devices");
    });
    
    let title_box = Box::new(Orientation::Vertical, 5);
    title_box.set_hexpand(true);
    
    let title = Label::new(Some("Wipe Options"));
    title.add_css_class("title-1");
    title.set_halign(gtk4::Align::Start);
    
    let selected_device = app_state.selected_device.clone();
    let device_label = Label::new(None);
    device_label.add_css_class("subtitle");
    device_label.add_css_class("dim-label");
    device_label.set_halign(gtk4::Align::Start);
    
    title_box.append(&title);
    title_box.append(&device_label);
    
    header_box.append(&back_button);
    header_box.append(&title_box);
    
    // Options section
    let options_frame = Frame::new(None);
    options_frame.set_margin_start(20);
    options_frame.set_margin_end(20);
    options_frame.set_margin_bottom(20);
    
    let options_box = Box::new(Orientation::Vertical, 0);
    
    // Quick wipe option
    let quick_option = create_wipe_option(
        "Quick Wipe",
        "Fast deletion of file system headers (not secure)",
        true
    );
    
    // Secure wipe option
    let secure_option = create_wipe_option(
        "Secure Wipe",
        "Multiple pass overwrite for secure data destruction",
        false
    );
    
    // Zero fill option
    let zero_option = create_wipe_option(
        "Zero Fill",
        "Fill entire device with zeros (balanced speed/security)",
        false
    );
    
    options_box.append(&quick_option);
    options_box.append(&Separator::new(Orientation::Horizontal));
    options_box.append(&secure_option);
    options_box.append(&Separator::new(Orientation::Horizontal));
    options_box.append(&zero_option);
    
    options_frame.set_child(Some(&options_box));
    
    // Action section
    let action_box = Box::new(Orientation::Horizontal, 10);
    action_box.set_margin_start(20);
    action_box.set_margin_end(20);
    action_box.set_margin_bottom(20);
    action_box.set_halign(gtk4::Align::End);
    
    let cancel_button = Button::with_label("Cancel");
    let stack_clone = app_state.stack.clone();
    cancel_button.connect_clicked(move |_| {
        stack_clone.set_visible_child_name("devices");
    });
    
    let wipe_button = Button::with_label("Start Wipe");
    wipe_button.add_css_class("destructive-action");
    let app_state_clone = app_state.clone();
    wipe_button.connect_clicked(move |_| {
        show_confirmation_dialog(&app_state_clone);
    });
    
    action_box.append(&cancel_button);
    action_box.append(&wipe_button);
    
    main_box.append(&header_box);
    main_box.append(&options_frame);
    main_box.append(&action_box);
    
    // Update device label when page is shown
    stack.connect_visible_child_notify(move |stack| {
        if let Some(visible_child) = stack.visible_child() {
            if stack.visible_child_name().as_deref() == Some("wipe-options") {
                if let Some(device_path) = selected_device.borrow().as_ref() {
                    device_label.set_text(&format!("Selected device: {}", device_path));
                }
            }
        }
    });
    
    stack.add_titled(&main_box, Some("wipe-options"), "Wipe Options");
}

fn create_wipe_option(title: &str, description: &str, default_selected: bool) -> Box {
    let option_box = Box::new(Orientation::Horizontal, 15);
    option_box.set_margin_top(15);
    option_box.set_margin_bottom(15);
    option_box.set_margin_start(15);
    option_box.set_margin_end(15);
    
    let radio = CheckButton::new();
    radio.set_active(default_selected);
    radio.set_valign(gtk4::Align::Start);
    
    let text_box = Box::new(Orientation::Vertical, 5);
    text_box.set_hexpand(true);
    
    let title_label = Label::new(Some(title));
    title_label.set_halign(gtk4::Align::Start);
    title_label.add_css_class("heading");
    
    let desc_label = Label::new(Some(description));
    desc_label.set_halign(gtk4::Align::Start);
    desc_label.add_css_class("dim-label");
    desc_label.set_wrap(true);
    
    text_box.append(&title_label);
    text_box.append(&desc_label);
    
    option_box.append(&radio);
    option_box.append(&text_box);
    
    option_box
}

fn show_confirmation_dialog(app_state: &AppState) {
    let device_path = app_state.selected_device.borrow().clone()
        .unwrap_or("Unknown device".to_string());
    
    let dialog = MessageDialog::builder()
        .transient_for(&app_state.window)
        .modal(true)
        .message_type(MessageType::Warning)
        .buttons(ButtonsType::None)
        .text("Confirm Device Wipe")
        .secondary_text(&format!(
            "This will permanently erase all data on {}.\n\nThis action cannot be undone. Are you sure you want to continue?",
            device_path
        ))
        .build();
    
    dialog.add_button("Cancel", gtk4::ResponseType::Cancel);
    dialog.add_button("Wipe Device", gtk4::ResponseType::Accept);
    dialog.set_default_response(gtk4::ResponseType::Cancel);
    
    let app_state_clone = app_state.clone();
    dialog.connect_response(move |dialog, response| {
        match response {
            gtk4::ResponseType::Accept => {
                dialog.close();
                start_wipe_process(&app_state_clone);
            }
            _ => dialog.close(),
        }
    });
    
    dialog.show();
}

fn start_wipe_process(app_state: &AppState) {
    let device_path = app_state.selected_device.borrow().clone()
        .unwrap_or("Unknown device".to_string());
    
    // This would typically start the actual wipe process
    // For now, just show a success message
    let dialog = MessageDialog::builder()
        .transient_for(&app_state.window)
        .modal(true)
        .message_type(MessageType::Info)
        .buttons(ButtonsType::Ok)
        .text("Wipe Process Started")
        .secondary_text(&format!(
            "Wiping process for {} has been initiated.\n\n(This is a demo - no actual wiping performed)",
            device_path
        ))
        .build();
    
    let stack_clone = app_state.stack.clone();
    dialog.connect_response(move |dialog, _| {
        dialog.close();
        stack_clone.set_visible_child_name("devices");
    });
    
    dialog.show();
}

fn main() {
    let app = Application::builder()
        .application_id("com.example.wiper")
        .build();
    
    app.connect_activate(build_ui);
    app.run();
}
