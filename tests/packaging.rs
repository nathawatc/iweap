use iweap::{
    AUTHORIZATION_ACTION, INTERFACE_NAME, IWD_DIRECTORY, IWD_DIRECTORY_MODE, OBJECT_PATH,
    SERVICE_NAME,
};
use std::fs;

fn data_file(path: &str) -> String {
    fs::read_to_string(format!("{}/data/{path}", env!("CARGO_MANIFEST_DIR")))
        .expect("read packaging file")
}

fn setting<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
    })
}

fn method_block<'a>(introspection: &'a str, name: &str) -> &'a str {
    let marker = format!("<method name=\"{name}\">");
    let start = introspection
        .find(&marker)
        .expect("method in introspection");
    let remainder = &introspection[start..];
    let end = remainder
        .find("</method>")
        .expect("method closing tag in introspection")
        + "</method>".len();
    &remainder[..end]
}

#[test]
fn cross_format_service_contract_is_synchronized() {
    let bus_policy = data_file("dbus/org.codeberg.iweap.conf");
    let activation = data_file("dbus/org.codeberg.iweap.service");
    let unit = data_file("systemd/org.codeberg.iweap.service");
    let polkit = data_file("org.codeberg.iweap.policy");

    assert!(bus_policy.contains(&format!("<allow own=\"{SERVICE_NAME}\"/>")));
    assert_eq!(
        bus_policy
            .matches(&format!("send_destination=\"{SERVICE_NAME}\""))
            .count(),
        2
    );
    assert_eq!(
        bus_policy
            .matches(&format!("send_interface=\"{INTERFACE_NAME}\""))
            .count(),
        2
    );

    assert_eq!(setting(&activation, "Name"), Some(SERVICE_NAME));
    assert_eq!(setting(&activation, "Exec"), Some("/bin/false"));
    let systemd_service = format!("{SERVICE_NAME}.service");
    assert_eq!(
        setting(&activation, "SystemdService"),
        Some(systemd_service.as_str())
    );
    assert_eq!(setting(&unit, "BusName"), Some(SERVICE_NAME));
    assert_eq!(
        setting(&unit, "ExecStart"),
        Some("/usr/lib/iweap/iweap-service")
    );
    assert!(polkit.contains(&format!("<action id=\"{AUTHORIZATION_ACTION}\">")));
    assert!(polkit.contains("<description>Inspect or install an IWD 802.1X profile</description>"));
    assert!(polkit.contains(
        "<message>Authentication is required to inspect or install an IWD 802.1X profile.</message>"
    ));

    assert_eq!(
        setting(&unit, "StateDirectory"),
        IWD_DIRECTORY.strip_prefix("/var/lib/")
    );
    assert_eq!(
        setting(&unit, "StateDirectoryMode").and_then(|value| u32::from_str_radix(value, 8).ok()),
        Some(IWD_DIRECTORY_MODE)
    );

    use zbus::proxy::Defaults;
    type Proxy<'a> = iweap::ipc::ProfileInstallerProxy<'a>;
    assert_eq!(
        <Proxy<'_> as Defaults>::INTERFACE
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(INTERFACE_NAME)
    );
    assert_eq!(
        <Proxy<'_> as Defaults>::DESTINATION
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(SERVICE_NAME)
    );
    assert_eq!(
        <Proxy<'_> as Defaults>::PATH
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(OBJECT_PATH)
    );
    assert_eq!(
        <iweap::InstallerService as zbus::object_server::Interface>::name().as_str(),
        INTERFACE_NAME
    );

    let service = iweap::InstallerService::new(iweap::Installer::system());
    let mut introspection = String::new();
    <iweap::InstallerService as zbus::object_server::Interface>::introspect_to_writer(
        &service,
        &mut introspection,
        0,
    );
    assert_eq!(introspection.matches("<method name=").count(), 2);
    for member in ["InspectProfile", "InstallProfile"] {
        assert!(bus_policy.contains(&format!("send_member=\"{member}\"")));
        assert!(introspection.contains(&format!("<method name=\"{member}\">")));
    }

    let inspect_method = method_block(&introspection, "InspectProfile");
    assert_eq!(inspect_method.matches("<arg ").count(), 2);
    assert!(inspect_method.contains("<arg name=\"ssid\" type=\"s\" direction=\"in\"/>"));
    assert!(inspect_method.contains("<arg type=\"(s(btttuuuxxtxt))\" direction=\"out\"/>"));

    use zbus::zvariant::Type;
    let install_request_sig = <iweap::InstallRequest as Type>::SIGNATURE.to_string();
    assert_eq!(
        install_request_sig,
        "((sa(ysssb(ssnyssss)))(btttuuuxxtxt)b)"
    );
    let install_arg =
        format!("<arg name=\"request\" type=\"{install_request_sig}\" direction=\"in\"/>");
    assert!(introspection.contains(&install_arg));
}
