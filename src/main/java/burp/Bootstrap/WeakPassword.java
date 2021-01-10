package burp.Bootstrap;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class WeakPassword
{
    public final List<Map.Entry<String, String>> credentials;

    public WeakPassword()
    {
        this.credentials = new ArrayList();
    }

    public void addCredential(Map.Entry<String, String> credential)
    {
        this.credentials.add(credential);
    }

    public List<Map.Entry<String, String>> getCredentials()
    {
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "tomcat"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "manager"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "password"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "changethis"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "s3cret"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", ""));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "123456"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "1qaz2wsx"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "qwer1234"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "!QAZ2wsx"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "Pass1234"));
        this.credentials.add(new AbstractMap.SimpleEntry("tomcat", "Passw0rd"));
        this.credentials.add(new AbstractMap.SimpleEntry("both", "manager"));
        this.credentials.add(new AbstractMap.SimpleEntry("both", "tomcat"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "manager"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", ""));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "tomcat"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "123456"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "1qaz2wsx"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "qwer1234"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "!QAZ2wsx"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "Pass1234"));
        this.credentials.add(new AbstractMap.SimpleEntry("manager", "Passw0rd"));
        this.credentials.add(new AbstractMap.SimpleEntry("role1", "role1"));
        this.credentials.add(new AbstractMap.SimpleEntry("role1", "tomcat"));
        this.credentials.add(new AbstractMap.SimpleEntry("role", "changethis"));
        this.credentials.add(new AbstractMap.SimpleEntry("root", "changethis"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "password"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "tomcat"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "manager"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "admin"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "admin123"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "root"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", ""));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "123456"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "1qaz2wsx"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "qwer1234"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "!QAZ2wsx"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "Pass1234"));
        this.credentials.add(new AbstractMap.SimpleEntry("admin", "Passw0rd"));
        this.credentials.add(new AbstractMap.SimpleEntry("test", "test"));
        this.credentials.add(new AbstractMap.SimpleEntry("guest", "guest"));
        this.credentials.add(new AbstractMap.SimpleEntry("root", ""));
        this.credentials.add(new AbstractMap.SimpleEntry("root", "root"));
        this.credentials.add(new AbstractMap.SimpleEntry("root", "admin"));
        this.credentials.add(new AbstractMap.SimpleEntry("root", "password"));
        this.credentials.add(new AbstractMap.SimpleEntry("root", "123456"));
        this.credentials.add(new AbstractMap.SimpleEntry("root", "root123"));

        return this.credentials;
    }
}
