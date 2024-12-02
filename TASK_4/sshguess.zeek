redef Log::print_to_log = Log::REDIRECT_ALL;
global failed_attempts: table[addr, addr] of count &default = 0;

event zeek_init(){
	print "Zeek started";
}
event ssh_auth_failed(c: connection) {
    failed_attempts[c$id$orig_h, c$id$resp_h] += 1;
	print fmt("Source IP: %s, Destination IP: %s and attempts %d", c$id$orig_h, c$id$resp_h,failed_attempts[c$id$orig_h, c$id$resp_h]);
	print("PRAMOD HEMBROM CS23MTECH11015");
}

event ssh_auth_successful(c: connection, auth_method_none: bool) {
    if (auth_method_none) {
        if (failed_attempts[c$id$orig_h, c$id$resp_h] > 0) {
            failed_attempts[c$id$orig_h, c$id$resp_h] = 0;
        }
    }
}


event zeek_done(){
	print fmt("Zeek stopped");

}
