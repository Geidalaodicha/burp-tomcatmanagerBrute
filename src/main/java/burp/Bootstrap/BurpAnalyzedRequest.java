//package burp.Bootstrap;
//import burp.*;
//
//import java.io.UnsupportedEncodingException;
//import java.util.ArrayList;
//import java.util.List;
//public class BurpAnalyzedRequest {
//    private IBurpExtenderCallbacks callbacks;
//    private IExtensionHelpers helpers;
//
//    private CustomHelpers customHelpers;
//
//    private List<IParameter> jsonParameters = new ArrayList<IParameter>();
//
//    private IHttpRequestResponse requestResponse;
//
//    public BurpAnalyzedRequest(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
//        this.callbacks = callbacks;
//        this.helpers = this.callbacks.getHelpers();
//
//        this.customHelpers = new CustomHelpers();
//
//        this.requestResponse = requestResponse;
//
//    }
//
//    public IHttpRequestResponse requestResponse() {
//        return this.requestResponse;
//    }
//
//    public IRequestInfo analyzeRequest() {
//        return this.helpers.analyzeRequest(this.requestResponse);
//    }
//
//
//}
