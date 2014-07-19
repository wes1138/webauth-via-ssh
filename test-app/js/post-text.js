/* NOTE: some assumptions are made on the page containing this script.
 * In particular, it is assumed to have
 * 1. a text area named "usertext" to hold the user's data, and
 * 2. a span named "savestatus" to hold the result of the POST.
 * */
function postText() {
	/* use xmlhttpreq to send new data */
	xmlhttp = new XMLHttpRequest();
	xmlhttp.onreadystatechange = function() {
		if (xmlhttp.readyState != 4) return;
		if (xmlhttp.status == 200) {
			document.getElementById("savestatus").innerHTML = "saved.";
		} else if (xmlhttp.status == 403) {
			/* forbidden.  would never happen during normal usage though. */
			document.getElementById("savestatus").innerHTML = "POST denied :\\";
		} else {
			document.getElementById("savestatus").innerHTML = "POST failed :\\";
		}
	}
	xmlhttp.open("POST","main.fcgi");
	xmlhttp.send(document.getElementById("usertext").value);
}
function clearMessage() {
	document.getElementById("savestatus").innerHTML = "";
}
