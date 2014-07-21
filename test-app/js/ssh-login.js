/* NOTE: at the moment, we assume there is a button with id rqbutton
 * that is used to request a token.  */
var websock = new WebSocket("ws://localhost:7681/");
window.onload = function() {
	websock.onopen = function(e) { document.getElementById("rqbutton").disabled=false; }
	websock.onclose = function(e) { document.getElementById("rqbutton").disabled=true; }
	websock.onmessage = function(e) {
	var reader = new window.FileReader();
	reader.onloadend = function() {
		var token = reader.result;
		token = token.replace(/data:.*;base64,/i,"");
		/* before setting the cookie, check the return code,
		 * which requires a little base64 decoding (not much).
		 * If we send *two* bytes of status code with the high
		 * order being the code and low order just a 0 for
		 * padding, then we can use a lookup table.  (XXX) */
		if (token.substring(0,2) == "AA") {
			token = token.substring(4);
			/* NOTE: "token" actually contained a 3-byte return code
			 * and the token.  3 bytes = 24 bits = 6*4, so we remove
			 * 4 characters of base64 to get just the token.  */
			document.getElementById("msgrecvd").value =
				"Token acquired :D\n" + token;
			// set the cookie:
			document.cookie = "auth-token=" + token + "; max-age=1800";
			/* TODO: and now redirect to the main page... */
		} else if (token.substring(0,2) == "AQ") {
			document.getElementById("msgrecvd").value =
				"Public key unknown to server :\\";
		} else if (token.substring(0,2) == "/w") {
			document.getElementById("msgrecvd").value =
				"SSH error.  Is ssh-agent running?";
		} else {
			document.getElementById("msgrecvd").value =
				"Server error x_x";
		}
		// XXX: after debugging (or setting up certificates on
		// localhost), you will want to add the secure flag:
		// document.cookie = "auth-token=" + token + "; secure";
		// TODO: set expires so that the cookie lasts longer
		// than a single session?  Or, have the browser replace this
		// token with an httponly / secure cookie immediately.  I think
		// that is the best policy.  That one must have expires set,
		// but the question of how long to make it last is still debatable.
	};
	reader.onerror = function(e) {
		document.getElementById("msgrecvd").value =
			"file reader failed with code " + e.target.error.code;
	};
	reader.readAsDataURL(e.data); // base64; cookie-friendly.
};
};
function sendMsg() {
  websock.send(document.getElementById('msgtosend').value);
}
function closeCnx() {
  websock.close();
}
