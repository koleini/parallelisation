open V1_LWT
open Lwt
open Printf

let red fmt    = sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = sprintf ("\027[36m"^^fmt^^"\027[m")

let total_packets_in = ref 0l
let pkt_count = ref 0l

module Main (C: CONSOLE)(N1: NETWORK)(N2: NETWORK) = struct

  module E = Ethif.Make(N1)

  let or_error c name fn t =
  fn t
	>>= function
	| `Error e -> fail (Failure ("error starting " ^ name))
	| `Ok t -> C.log_s c (green "%s connected..." name) >>
			   return t

  let (in_queue, in_push) = Lwt_stream.create ()
  let (out_queue, out_push) = Lwt_stream.create ()

  let listen intf =
	let hw_addr =  Macaddr.to_string (E.mac intf) in
	let _ = printf "listening on the interface with mac address '%s' \n%!" hw_addr in
	return (N1.listen (E.id intf) (fun frame -> return (in_push (Some frame))) )

  let update_packet_count () =
	let _ = pkt_count := Int32.succ !pkt_count in
	let _ = total_packets_in := Int32.succ !total_packets_in in
	if (Int32.logand !total_packets_in 0x3fffl) = 0l then
		let _ = printf "packets in = %ld | not processed = %ld" !total_packets_in !pkt_count in 
		print_endline ""

  let start console n1 n2 =

  let forward_thread intf =
	  while_lwt true do
        lwt _ = Lwt_stream.next in_queue >>= fun frame -> return (out_push (Some frame)) in
		let _ = update_packet_count () in
		return ()
	  done  
	  <?> (
		(* 1. limiting the number of running output threads *)
		let max_threads = 10 in
		let rec forward threads num_of_threads =
	  	  Lwt_stream.next out_queue >>= fun frame ->
		  let _ = pkt_count := Int32.pred !pkt_count in
		  if num_of_threads < max_threads then
		    forward (frame::threads) (num_of_threads + 1)
		  else
		    Lwt.join (List.map (fun f -> (E.write intf f)) (frame::threads)) 
		    >> forward [] 0
		in
	  		forward [] 0

		(* 2. Number of running threads is not bounded *)
		(*
		let rec forward queue =
		  Lwt_stream.next queue >>= fun frame ->
		  let _ = pkt_count := Int32.pred !pkt_count in
			Lwt.ignore_result (E.write intf frame);
			forward queue
		in
	  	  forward out_queue
		*)

		(* 3. Serialisation *)
		(*
		while_lwt true do
		  lwt frame = Lwt_stream.next out_queue in
		  	let _ = pkt_count := Int32.pred !pkt_count in
		  	E.write intf frame
		done
		*)
			
	  )
  in
  lwt if2 = or_error console "interface" E.connect n1 in
  lwt if1 = or_error console "interface" E.connect n2 in
  listen if1
  >> forward_thread if2
  >> return (print_endline "terminated...")

end
