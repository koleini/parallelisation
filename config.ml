open Mirage

let main = foreign "Unikernel.Main" (console @-> network @-> network @-> job)

let unix_libs =
  match get_mode () with 
  | `Unix -> ["mirage-clock-unix"] 
  | _ -> []

let net =
  try match Sys.getenv "NET" with
    | "direct" -> `Direct
    | "socket" -> `Socket
    | _ -> `Direct
  with Not_found -> `Direct

let dhcp =
  try match Sys.getenv "ADDR" with
    | "dhcp" -> `Dhcp
    | "static" -> `Static
  with Not_found -> `Dhcp

let stack console =
  match net, dhcp with
  | `Direct, `Dhcp -> direct_stackv4_with_dhcp console tap0 
  | `Direct, `Static -> direct_stackv4_with_default_ipv4 console tap0
  | `Direct, _ -> direct_stackv4_with_default_ipv4 console tap0
  | `Socket, _ -> socket_stackv4 console [Ipaddr.V4.any]

let tracing = mprof_trace ~size:1000000 ()

let () =
  add_to_ocamlfind_libraries
    ([ "tcpip.ethif"; "tcpip.tcpv4"; "tcpip.udpv4"; "tcpip.dhcpv4"; "tcpip.channel"; "cstruct.syntax"; "core_kernel"; "sexplib"; "sexplib.syntax"; "packet"; ] @ unix_libs);

  register "ofswitch" ~tracing [
    main $ default_console $ (netif "1") $ (netif "2")
  ]
