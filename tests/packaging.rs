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

fn action_block<'a>(policy: &'a str, id: &str) -> &'a str {
    let marker = format!("<action id=\"{id}\">");
    let start = policy.find(&marker).expect("action in policy");
    let remainder = &policy[start..];
    let end = remainder
        .find("</action>")
        .expect("action closing tag in policy")
        + "</action>".len();
    &remainder[..end]
}

fn element_text<'a>(xml: &'a str, element: &str) -> &'a str {
    let mut matches = Vec::new();
    let open_prefix = format!("<{element}");
    let close_prefix = format!("</{element}");

    let mut search_idx = 0;
    while let Some(start) = xml[search_idx..].find(&open_prefix) {
        let tag_start = search_idx + start;
        let after_prefix = &xml[tag_start + open_prefix.len()..];
        if let Some(first_char) = after_prefix.chars().next() {
            if first_char == '>' || first_char.is_ascii_whitespace() {
                let tag_end_rel = after_prefix.find('>').expect("closing '>' for opening tag");
                let content_start = tag_start + open_prefix.len() + tag_end_rel + 1;
                let remainder = &xml[content_start..];
                let close_start_rel = remainder.find(&close_prefix).expect("closing tag start");
                let after_close_prefix = &remainder[close_start_rel + close_prefix.len()..];
                let close_first_char = after_close_prefix
                    .chars()
                    .next()
                    .expect("character after closing tag name");
                assert!(
                    close_first_char == '>' || close_first_char.is_ascii_whitespace(),
                    "closing tag prefix matched unexpected tag name"
                );
                let body = &remainder[..close_start_rel];
                matches.push(body.trim());
            }
        }
        search_idx = tag_start + open_prefix.len();
    }

    assert_eq!(
        matches.len(),
        1,
        "expected exactly one <{element}> in XML block, found {}",
        matches.len()
    );
    matches[0]
}

#[test]
fn element_text_helper_handles_whitespace_and_rejects_duplicates() {
    let single = "<allow_any>\n    no\n</allow_any>";
    assert_eq!(element_text(single, "allow_any"), "no");

    let with_space = "<allow_any >no</allow_any>";
    assert_eq!(element_text(with_space, "allow_any"), "no");
}

#[test]
#[should_panic(expected = "expected exactly one <allow_any>")]
fn element_text_helper_rejects_duplicate_tags() {
    let duplicate = "<allow_any>no</allow_any><allow_any>yes</allow_any>";
    let _ = element_text(duplicate, "allow_any");
}

#[test]
#[should_panic(expected = "expected exactly one <allow_any>")]
fn element_text_helper_rejects_duplicate_tags_with_spaces() {
    let duplicate = "<allow_any>no</allow_any><allow_any >yes</allow_any>";
    let _ = element_text(duplicate, "allow_any");
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
    let polkit_action = action_block(&polkit, AUTHORIZATION_ACTION);
    assert_eq!(
        element_text(polkit_action, "description"),
        "Inspect or install an IWD 802.1X profile"
    );
    assert_eq!(
        element_text(polkit_action, "message"),
        "Authentication is required to inspect or install an IWD 802.1X profile."
    );
    assert_eq!(element_text(polkit_action, "allow_any"), "no");
    assert_eq!(element_text(polkit_action, "allow_inactive"), "no");
    assert_eq!(
        element_text(polkit_action, "allow_active"),
        "auth_admin_keep"
    );

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
