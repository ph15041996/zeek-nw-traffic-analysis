redef Log::print_to_log = Log::REDIRECT_ALL;

event zeek_init(){
	print "Zeek started";
	# initilaization is done here
}



event connection_established(c:connection)
{
	if(c$id$resp_h == 104.154.89.105){
	print fmt("Zeek connection established from %s:%s to %s:%s ",c$id$orig_h,c$id$orig_p,c$id$resp_h,c$id$resp_p);
	}
}

event ssl_established(c: connection){

	if(c$id$resp_h == 104.154.89.105){
		local cert_chain =c$ssl$cert_chain;
		if(|cert_chain|>0){
			local last_cert = cert_chain[|cert_chain|-1];
			local last_cert_subject =last_cert$x509$certificate$subject; 
			local last_cert_issuer =last_cert$x509$certificate$issuer; 
			print("The self-signed certificate is ");
			print fmt("%s",last_cert$x509);
			print fmt("The subject is %s",last_cert_subject);
			print fmt("The issuer is %s",last_cert_issuer);
			if(last_cert_issuer == last_cert_subject){
			print("This is a self self-signed certificate");
			print("");
			}
		}
		else{
			print("No certificate found");
		}
	}
}


event connection_finished(c:connection)
{
	if(c$id$resp_h == 104.154.89.105){
	print fmt("Zeek connection finished from %s:%s to %s:%s ",c$id$orig_h,c$id$orig_p,c$id$resp_h,c$id$resp_p);
	}

}
event zeek_done(){
	# Clean up is done here
	print fmt("Zeek stopped");

}











