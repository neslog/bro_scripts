@load /opt/bro/share/bro/base/protocols/ssl
module SSL;

redef record SSL::Info += {
     certificate_version:	count           &log &optional;
     certificate_serial:	string		 &log &optional;
     certificate_subject:	string           &log &optional;
     certificate_issuer:	string           &log &optional;
     certificate_not_valid_before:	time           &log &optional;
     certificate_not_valid_after:	time           &log &optional;
     certificate_key_alg:	string           &log &optional;
     certificate_sig_alg:	string           &log &optional;
     certificate_key_type:	string           &log &optional;
     certificate_key_length:	int              &log &optional;
     certificate_exponent:	string              &log &default = "";
     certificate_curve:		string           &log &optional;
     san_dns:			string           &log &optional;
     san_uri:			string           &log &optional;
     san_email:			string           &log &optional;
     san_ip:			string           &log &optional;
     basic_constraints_ca:	string           &log &optional;
     basic_constraints_path_len:	string           &log &optional;
};



event connection_state_remove(c: connection) &priority=-5
{
if ( c?$ssl) {
  if ( c$ssl?$cert_chain ) {
  if ( !c$ssl$cert_chain[0]$x509$certificate?$exponent ) { c$ssl$cert_chain[0]$x509$certificate$exponent = ""; }
  if ( !c$ssl$cert_chain[0]$x509$certificate?$curve ) { c$ssl$cert_chain[0]$x509$certificate$curve = ""; }
  if ( !c$ssl$cert_chain[0]$x509$san?$uri ) { c$ssl$cert_chain[0]$x509$san$uri = [""]; }
  if ( !c$ssl$cert_chain[0]$x509$san?$email ) { c$ssl$cert_chain[0]$x509$san$email = [""]; }
  if ( !c$ssl$cert_chain[0]$x509$san?$ip ) { c$ssl$cert_chain[0]$x509$san$ip = [""]; }
#print "############### CONNECTION #################";
#print "";
#print c$ssl$cert_chain[0]$x509$certificate$issuer;
	c$ssl$certificate_version = c$ssl$cert_chain[0]$x509$certificate$version;
	c$ssl$certificate_serial = c$ssl$cert_chain[0]$x509$certificate$serial;
	c$ssl$certificate_subject = c$ssl$cert_chain[0]$x509$certificate$subject;
	c$ssl$certificate_issuer = "\""+c$ssl$cert_chain[0]$x509$certificate$issuer+"\"";
	c$ssl$certificate_not_valid_before = c$ssl$cert_chain[0]$x509$certificate$not_valid_before;
	c$ssl$certificate_not_valid_after = c$ssl$cert_chain[0]$x509$certificate$not_valid_after;
	c$ssl$certificate_key_alg = c$ssl$cert_chain[0]$x509$certificate$key_alg;
	c$ssl$certificate_sig_alg = c$ssl$cert_chain[0]$x509$certificate$sig_alg;
	c$ssl$certificate_key_type = c$ssl$cert_chain[0]$x509$certificate$key_type;
	c$ssl$certificate_key_length = c$ssl$cert_chain[0]$x509$certificate$key_length;
	c$ssl$certificate_exponent = c$ssl$cert_chain[0]$x509$certificate$exponent;
	c$ssl$certificate_curve = c$ssl$cert_chain[0]$x509$certificate$curve;
	c$ssl$san_dns = cat(c$ssl$cert_chain[0]$x509$san$dns);
	c$ssl$san_uri = cat(c$ssl$cert_chain[0]$x509$san$uri);
	c$ssl$san_email = cat(c$ssl$cert_chain[0]$x509$san$email);
	c$ssl$san_ip = cat(c$ssl$cert_chain[0]$x509$san$ip);

#print c$ssl$cert_chain[0]$x509$san;
#print "";
#print "############################################";
    }
  }
}
