use std::fs;

const DBUS_SERVICE_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/dbus/org.codeberg.iweap.service"
);

#[test]
fn dbus_activation_is_fail_closed_and_systemd_owned() {
    let service = fs::read_to_string(DBUS_SERVICE_FILE).expect("read D-Bus service file");

    assert!(
        service
            .lines()
            .any(|line| line == "Name=org.codeberg.iweap")
    );
    assert!(
        service
            .lines()
            .any(|line| line == "SystemdService=org.codeberg.iweap.service")
    );
    assert!(service.lines().any(|line| line == "Exec=/bin/false"));
    assert!(!service.contains("Exec=/usr/lib/iweap/iweap-service"));
}
