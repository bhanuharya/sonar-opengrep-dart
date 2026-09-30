// Intentionally vulnerable sample: most rules in the bundled pack fire here once.
// It is scan input only; it is not meant to compile against real packages.
import 'dart:developer' as developer;
import 'dart:io';

class Api {
  final base = Uri.parse("http://api.example.com/v1");
  final headers = {"Content-Type": "application/json", "x-api-key": "not-a-real-key-example"};

  HttpClient insecureClient() {
    final client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true;
    return client;
  }
}

Future<void> saveSession(SharedPreferences prefs, String token) async {
  await prefs.setString("access_token", token);
  print("session saved, token=$token");
  developer.log("token refreshed: $token");
}

void openBridge(WebViewController controller) {
  controller.setJavaScriptMode(JavaScriptMode.unrestricted);
  controller.addJavaScriptChannel("Bridge", onMessageReceived: (message) => handle(message.message));
}

String encrypt(Key key, String plain) {
  final iv = IV.fromLength(16);
  return Encrypter(AES(key)).encrypt(plain, iv: iv).base64;
}

Future<bool> confirmPayment(LocalAuthentication auth) {
  return auth.authenticate(localizedReason: "Confirm payment", options: const AuthenticationOptions(biometricOnly: false));
}

void listenForLinks(AppLinks appLinks) {
  appLinks.uriLinkStream.listen((uri) => open(uri));
}
