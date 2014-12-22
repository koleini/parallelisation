open V1_LWT
open Lwt
open Printf
open OS

let red fmt    = sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = sprintf ("\027[36m"^^fmt^^"\027[m")

let total_packets_in = ref 0l
let pkt_count = ref 0l

module Main (C: CONSOLE)(N2: NETWORK) = struct

  module E2 = Ethif.Make(N2)

  let or_error c name fn t =
  fn t
	>>= function
	| `Error e -> fail (Failure ("error starting " ^ name))
	| `Ok t -> C.log_s c (green "%s connected..." name) >>
			   return t

  let (in_queue, in_push) = Lwt_stream.create ()
  let (out_queue, out_push) = Lwt_stream.create ()

  let listen nf =
	let hw_addr =  Macaddr.to_string (E2.mac nf) in
	let _ = printf "listening on the interface with mac address '%s' \n%!" hw_addr in
	N2.listen (E2.id nf) (fun frame -> return (in_push (Some frame)))

  let update_packet_count () =
	let _ = pkt_count := Int32.succ !pkt_count in
	let _ = total_packets_in := Int32.succ !total_packets_in in
	if (Int32.logand !total_packets_in 0x3fffl) = 0l then
		let _ = printf "packets in = %ld | not processed = %ld" !total_packets_in !pkt_count in 
		print_endline ""

(*
  let check_ring intf =
	while_lwt true do
		OS.Time.sleep 2.0 >>
		let nf = E2.id intf in
		let stats = N2.get_stats_counters nf in
		let _ = printf "mac: %s\n\t rx_pkts: %ld, tx_pkts: %ld\n" (Macaddr.to_string (E2.mac intf)) stats.rx_pkts stats.tx_pkts in
		let _ = Activations.dump () in
		return (print_endline "")
	done
*)

  let start console n2 =

  let forward_thread =
	  while_lwt true do
        lwt _ = Lwt_stream.next in_queue >>= fun frame -> return (out_push (Some frame)) in
		let _ = update_packet_count () in
		return ()
	  done  
	  <?> (
	  while_lwt true do
		Lwt_stream.next out_queue >>=
		  fun _ -> 
			let _ = pkt_count := Int32.pred !pkt_count in
			return ()
	  done
	  )
  in
  lwt nf = or_error console "interface" E2.connect n2 in
  (listen nf) <?> (forward_thread) (* <?> (check_ring' nf) *)
  >> return (print_endline "terminated...")

end
