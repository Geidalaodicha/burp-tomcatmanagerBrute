package burp;

import burp.Bootstrap.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;
import java.util.Map;

import burp.Bootstrap.*;

public class BurpExtender implements IBurpExtender,IScannerCheck{
    private Tags tags;
    public static String NAME = "TomcatManager";
    public static String VERSION = "0.1";

    private DomainNameRepeat domainNameRepeat;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.tags = new Tags(callbacks, NAME);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.domainNameRepeat = new DomainNameRepeat();
        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout.println("=============================");
        this.stdout.println("[+]    load successful!      ");
        this.stdout.println("[+] TomcatManagerBrute v0.1  ");
        this.stdout.println("[+]    code by p4ssw0rd      ");
        this.stdout.println("=============================");

    }




    private URL getUrl(String host_managerUrl) {
        try {
            URL url = new URL(host_managerUrl);
            Boolean isSSL = Boolean.valueOf(url.getProtocol().equals("https"));
            byte[] httpAuthTest = this.helpers.buildHttpRequest(url);
            byte[] response = this.callbacks.makeHttpRequest(url.getHost(), url.getPort(), isSSL.booleanValue(), httpAuthTest);
            int host_managerCode = this.helpers.analyzeResponse(response).getStatusCode();
            if(host_managerCode==401){
                return url;
            }else{
                return null;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param baseRequestDomainName 当前请求的域名
     * @return
     */
    public URL getTomcatHostManager(String baseRequestDomainName) {

        String host_managerUrl = baseRequestDomainName+"/host-manager/html";
        return getUrl(host_managerUrl);
    }
    public URL getTomcatManager(String baseRequestDomainName) {

        String managerUrl = baseRequestDomainName+"/manager/html";
        return getUrl(managerUrl);
    }

    /**
     *
     * @param url manager链接对象
     * @return
     */
    public String BruteTomcat(URL url){

        WeakPassword wp = new WeakPassword();
        List<Map.Entry<String, String>> credentials = wp.getCredentials();
        for (Map.Entry<String, String> credential : credentials) {
            try {
                List<String> header = new ArrayList<>();

                String username = (String) credential.getKey();
                String password = (String) credential.getValue();
                header.add("GET "+url.getPath()+" HTTP/1.1");
                header.add("Host: "+ url.getHost() + ":" + url.getPort());
                header.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0");
                header.add("Referer: http://127.0.0.1/");
                header.add("Authorization: Basic " + helpers
                        .base64Encode(new StringBuilder().append(username).append(":").append(password).toString()));
                byte[] makeHttpRequest = this.helpers.buildHttpMessage(header, null);
                Boolean isSSL = Boolean.valueOf(url.getProtocol().equals("https"));
                byte[] responseWeakPassword = this.callbacks.makeHttpRequest(url.getHost(), url.getPort(), isSSL.booleanValue(), makeHttpRequest);
                if(this.helpers.analyzeResponse(responseWeakPassword).getStatusCode()==200){
                    return username + ":" + password;
                }else if(this.helpers.analyzeResponse(responseWeakPassword).getStatusCode()==403){
                    return username + ":" + password+" but not allowed us to manager.";
                }
            } catch (Exception e) {
                stderr.println(e.getMessage());
            }
        }
        return  null;

    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        List<IScanIssue> issues = new ArrayList();
        String baseRequestProtocol = baseRequestResponse.getHttpService().getProtocol();
        String baseRequestHost = baseRequestResponse.getHttpService().getHost();
        int baseRequestPort = baseRequestResponse.getHttpService().getPort();
        String baseRequestDomainName = baseRequestProtocol + "://" + baseRequestHost + ":" + baseRequestPort;
        if (this.domainNameRepeat.check(baseRequestDomainName)){
            return null;
        }
        this.domainNameRepeat.add(baseRequestDomainName);
        if (getTomcatManager(baseRequestDomainName)!=null)
        {
            URL url=getTomcatManager(baseRequestDomainName);
            stdout.println(url);
            byte[] baseResponse = baseRequestResponse.getResponse();
            int tagId = this.tags.add(
                    url.toString(),
                    this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                    "waiting for test results",
                    baseRequestResponse
            );
            String result=BruteTomcat(url);
            if (result !=null){
                this.tags.save(
                        tagId,
                        url.toString(),
                        this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                        "[+] Found password: "+result,
                        baseRequestResponse
                );

            }else{
                this.tags.save(
                        tagId,
                        url.toString(),
                        this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                        "[-] Not Found password",
                        baseRequestResponse
                );
            }
        }
        else if (getTomcatHostManager(baseRequestDomainName)!=null){
            URL url=getTomcatHostManager(baseRequestDomainName);
            stdout.println(url);
            byte[] baseResponse = baseRequestResponse.getResponse();
            int tagId = this.tags.add(
                    url.toString(),
                    this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                    "waiting for test results",
                    baseRequestResponse
            );
            String result=BruteTomcat(url);
            if (result !=null){
                this.tags.save(
                        tagId,
                        url.toString(),
                        this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                        "[+] Found password: "+result,
                        baseRequestResponse
                );

            }else{
                this.tags.save(
                        tagId,
                        url.toString(),
                        this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                        "[-] Not found password",
                        baseRequestResponse
                );
            }

        }else{
            stdout.println(baseRequestDomainName+" Not found");
        }
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        }
        return 0;
    }
}
