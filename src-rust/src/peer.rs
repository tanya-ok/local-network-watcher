//! Who is on the other end: the account behind a loopback TCP client, read from the kernel socket table, and the account behind a Unix socket peer.

use std::net::Ipv4Addr;

/// uid used when the owner cannot be found; never on any admin list.
pub const UNKNOWN_UID: u32 = u32::MAX;

const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;
const XINPGEN_LEN: usize = 24;

type End = (Option<Ipv4Addr>, u16);

/// One TCP socket from net.inet.tcp.pcblist_n: ports in host order, IPv4 addresses when the socket is IPv4.
#[derive(Debug, Clone, PartialEq)]
pub struct TcpOwner {
    pub local: End,
    pub remote: End,
    pub uid: u32,
    pub pid: i32,
}

fn u16_be(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_ne(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

// Offsets of xinpcb_n and xsocket_n, checked against a live socket by the finds_own_loopback_client test.
const INP_FPORT: usize = 16;
const INP_LPORT: usize = 18;
const INP_VFLAG: usize = 44;
const INP_FADDR4: usize = 48 + 12;
const INP_LADDR4: usize = 64 + 12;
const SO_UID: usize = 64;
const SO_LAST_PID: usize = 68;
const INP_IPV4: u8 = 0x1;

/// Parses the raw sysctl buffer. Each socket is a group of records; a group is complete once its socket and inpcb records are both seen.
pub fn parse_pcblist(buf: &[u8]) -> Vec<TcpOwner> {
    let mut out = Vec::new();
    let Some(first) = u32_ne(buf, 0) else {
        return out;
    };
    let mut at = (first as usize + 7) & !7;
    let mut so: Option<(u32, i32)> = None;
    let mut inp: Option<(End, End)> = None;
    while let (Some(len), Some(kind)) = (u32_ne(buf, at), u32_ne(buf, at + 4)) {
        let len = len as usize;
        if len <= XINPGEN_LEN || at + len > buf.len() {
            break;
        }
        let rec = &buf[at..at + len];
        match kind {
            XSO_SOCKET => {
                so = u32_ne(rec, SO_UID).zip(u32_ne(rec, SO_LAST_PID).map(|p| p as i32));
            }
            XSO_INPCB => {
                let v4 = rec.get(INP_VFLAG).is_some_and(|f| f & INP_IPV4 != 0);
                let addr = |o: usize| {
                    v4.then(|| rec.get(o..o + 4))
                        .flatten()
                        .map(|a| Ipv4Addr::new(a[0], a[1], a[2], a[3]))
                };
                if let (Some(lp), Some(fp)) = (u16_be(rec, INP_LPORT), u16_be(rec, INP_FPORT)) {
                    inp = Some(((addr(INP_LADDR4), lp), (addr(INP_FADDR4), fp)));
                }
            }
            _ => {}
        }
        if let (Some((uid, pid)), Some((local, remote))) = (so, inp) {
            out.push(TcpOwner {
                local,
                remote,
                uid,
                pid,
            });
            so = None;
            inp = None;
        }
        at += (len + 7) & !7;
    }
    out
}

fn sysctl_direct() -> Option<Vec<u8>> {
    let name = c"net.inet.tcp.pcblist_n";
    for _ in 0..4 {
        let mut size: libc::size_t = 0;
        // SAFETY: a size query with a null buffer.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        size += size / 4 + 4096;
        let mut buf = vec![0u8; size];
        // SAFETY: buf is valid for size bytes and the kernel writes at most size.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(size);
            return Some(buf);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

fn sysctl_tool() -> Option<Vec<u8>> {
    let out = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-b", "net.inet.tcp.pcblist_n"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// The socket table read both directly and through the system sysctl tool. A process in a GUI session without Local Network access may be shown only its own sockets; then other accounts' clients do not match and stay unknown.
fn owners() -> Vec<TcpOwner> {
    let mut all: Vec<TcpOwner> = [sysctl_direct(), sysctl_tool()]
        .into_iter()
        .flatten()
        .flat_map(|b| parse_pcblist(&b))
        .collect();
    let mut unique: Vec<TcpOwner> = Vec::with_capacity(all.len());
    for o in all.drain(..) {
        if !unique.contains(&o) {
            unique.push(o);
        }
    }
    unique
}

/// What the socket table looks like to this process: raw bytes per source, sockets parsed, distinct uids.
pub fn socket_table_diag() -> serde_json::Value {
    let src = |b: Option<Vec<u8>>| {
        let owners = b.as_deref().map(parse_pcblist).unwrap_or_default();
        let mut uids: Vec<u32> = owners.iter().map(|o| o.uid).collect();
        uids.sort_unstable();
        uids.dedup();
        serde_json::json!({ "bytes": b.map(|v| v.len()), "sockets": owners.len(), "uids": uids })
    };
    serde_json::json!({ "uid": unsafe { libc::getuid() }, "direct": src(sysctl_direct()), "tool": src(sysctl_tool()) })
}

/// The owner of the client end of a loopback connection: the socket whose local end is client:client_port and whose remote end is server:server_port. Exactly one match, or None.
pub fn match_client(
    owners: &[TcpOwner],
    client: Ipv4Addr,
    client_port: u16,
    server: Ipv4Addr,
    server_port: u16,
) -> Option<&TcpOwner> {
    let mut found = owners.iter().filter(|o| {
        o.local == (Some(client), client_port) && o.remote == (Some(server), server_port)
    });
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

/// uid of the process that opened a loopback TCP connection to us, or UNKNOWN_UID.
pub fn tcp_client_uid(client: std::net::SocketAddr, server: std::net::SocketAddr) -> u32 {
    let (std::net::IpAddr::V4(c), std::net::IpAddr::V4(s)) = (client.ip(), server.ip()) else {
        return UNKNOWN_UID;
    };
    if let Some(o) = match_client(&owners(), c, client.port(), s, server.port()) {
        return o.uid;
    }
    // lsof sees the caller's own account's processes even where the socket table is filtered.
    let name = format!("{c}:{}->{s}:{}", client.port(), server.port());
    std::process::Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            &format!("-iTCP:{}", client.port()),
            "-sTCP:ESTABLISHED",
            "-F",
            "pun",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|o| lsof_owner(&String::from_utf8_lossy(&o.stdout), &name))
        .unwrap_or(UNKNOWN_UID)
}

/// The single uid in `lsof -F pun` output that holds a file named exactly `name`.
pub fn lsof_owner(text: &str, name: &str) -> Option<u32> {
    let mut uid = None;
    let mut found: Vec<u32> = Vec::new();
    for line in text.lines() {
        match line.split_at_checked(1) {
            Some(("p", _)) => uid = None,
            Some(("u", u)) => uid = u.parse().ok(),
            Some(("n", n)) if n == name => {
                if let Some(u) = uid
                    && !found.contains(&u)
                {
                    found.push(u);
                }
            }
            _ => {}
        }
    }
    (found.len() == 1).then(|| found[0])
}

/// uid of a Unix socket peer, from the kernel (getpeereid).
pub fn unix_peer_uid(fd: std::os::fd::RawFd) -> u32 {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: fd is an open socket; uid and gid are valid out pointers.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } == 0 {
        uid
    } else {
        UNKNOWN_UID
    }
}

pub fn user_name(uid: u32) -> String {
    if uid == UNKNOWN_UID {
        return "unknown".into();
    }
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; the name is copied before buf is dropped.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return uid.to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }
        .to_string_lossy()
        .into_owned()
}

/// Whether uid is a member of the named group, primary or supplementary, as the directory reports it.
pub fn in_group(uid: u32, group: &str) -> bool {
    if uid == UNKNOWN_UID {
        return false;
    }
    let Ok(gname) = std::ffi::CString::new(group) else {
        return false;
    };
    // SAFETY: getgrnam returns static storage or null; only gr_gid is read at once.
    let grp = unsafe { libc::getgrnam(gname.as_ptr()) };
    if grp.is_null() {
        return false;
    }
    let gid = unsafe { (*grp).gr_gid };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: valid pointers as in user_name.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return false;
    }
    if pw.pw_gid == gid {
        return true;
    }
    let mut groups = vec![0 as libc::c_int; 256];
    let mut n = groups.len() as libc::c_int;
    // SAFETY: groups holds n entries; getgrouplist updates n.
    unsafe {
        libc::getgrouplist(
            pw.pw_name,
            pw.pw_gid as libc::c_int,
            groups.as_mut_ptr(),
            &mut n,
        );
    }
    groups
        .iter()
        .take(n.max(0) as usize)
        .any(|g| *g as u32 == gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_own_loopback_client() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, peer) = listener.accept().unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
        let me = unsafe { libc::getuid() };
        assert_eq!(tcp_client_uid(peer, server), me);
        let owners = owners();
        let std::net::IpAddr::V4(ip) = peer.ip() else {
            panic!()
        };
        let o = match_client(&owners, ip, peer.port(), ip, server.port()).unwrap();
        assert_eq!(o.pid, std::process::id() as i32);
        // The accepted end is a separate entry with the reverse direction.
        assert!(match_client(&owners, ip, server.port(), ip, peer.port()).is_some());
        assert_eq!(
            tcp_client_uid(
                std::net::SocketAddr::new(peer.ip(), 1),
                std::net::SocketAddr::new(peer.ip(), 2)
            ),
            UNKNOWN_UID
        );
    }

    #[test]
    fn lsof_lines() {
        let text = "p10\nu501\nf4\nn127.0.0.1:5000->127.0.0.1:4317\nf5\nn127.0.0.1:4317->127.0.0.1:5000\np11\nu504\nf3\nn127.0.0.1:5001->127.0.0.1:4317\n";
        assert_eq!(
            lsof_owner(text, "127.0.0.1:5000->127.0.0.1:4317"),
            Some(501)
        );
        assert_eq!(
            lsof_owner(text, "127.0.0.1:5001->127.0.0.1:4317"),
            Some(504)
        );
        assert_eq!(lsof_owner(text, "127.0.0.1:500->127.0.0.1:4317"), None);
        let two = "p1\nu501\nn127.0.0.1:1->127.0.0.1:2\np2\nu504\nn127.0.0.1:1->127.0.0.1:2\n";
        assert_eq!(
            lsof_owner(two, "127.0.0.1:1->127.0.0.1:2"),
            None,
            "ambiguous owners stay unknown"
        );
    }

    #[test]
    fn admin_group_and_names() {
        assert!(in_group(0, "wheel"));
        assert!(!in_group(UNKNOWN_UID, "admin"));
        assert_eq!(user_name(0), "root");
        assert_eq!(user_name(UNKNOWN_UID), "unknown");
    }
}
