import Foundation
import SafariServices
import Security
final class SafariWebExtensionHandler:NSObject,NSExtensionRequestHandling {
    func beginRequest(with context:NSExtensionContext) {
        guard let input = context.inputItems.first as? NSExtensionItem,let message = input.userInfo?[SFExtensionMessageKey] as? [String:Any],let action = message["action"] as? String,["list","get","save"].contains(action),let url = message["url"] as? String,let origin = URLComponents(string:url),["https","http"].contains(origin.scheme ?? ""),origin.host != nil else {respond(context,["ok":false,"error":"Invalid native extension request"]);return}
        var q:[String:Any] = [kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"com.john.jjvault.safari.token",kSecAttrAccount as String:"browser",kSecReturnData as String:true]
        if let group = Bundle.main.object(forInfoDictionaryKey:"JJVaultKeychainGroup") as? String {q[kSecAttrAccessGroup as String] = group}
        var result:CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary,&result) == errSecSuccess,let data = result as? Data,let token = String(data:data,encoding:.utf8)else{respond(context,["ok":false,"error":"Pair JJ Vault for Safari first"]);return}
        var request = URLRequest(url:URL(string:"http://127.0.0.1:17373/browser")!);request.httpMethod = "POST";request.timeoutInterval = 10;request.setValue("Bearer "+token,forHTTPHeaderField:"Authorization");request.setValue("application/json",forHTTPHeaderField:"Content-Type")
        do{request.httpBody = try JSONSerialization.data(withJSONObject:message)}catch{respond(context,["ok":false,"error":"Invalid message"]);return}
        let config = URLSessionConfiguration.ephemeral;config.httpShouldSetCookies = false;config.urlCache = nil
        let session = URLSession(configuration:config,delegate:NoRedirect(),delegateQueue:nil)
        session.dataTask(with:request){data,response,error in defer{session.finishTasksAndInvalidate()};guard let data,let object = try? JSONSerialization.jsonObject(with:data) as? [String:Any]else{self.respond(context,["ok":false,"error":"Open JJ Vault on your Mac and unlock it"]);return};self.respond(context,object)}.resume()
    }
    func respond(_ context:NSExtensionContext,_ response:[String:Any]){let item = NSExtensionItem();item.userInfo = [SFExtensionMessageKey:response];context.completeRequest(returningItems:[item])}
}
private final class NoRedirect:NSObject,URLSessionTaskDelegate {func urlSession(_ session:URLSession,task:URLSessionTask,willPerformHTTPRedirection response:HTTPURLResponse,newRequest request:URLRequest,completionHandler:@escaping(URLRequest?)->Void){completionHandler(nil)}}
