# .NET CORE SDK
This is the GoodID SDK, written in Microsoft .NET Core 2.2
## Installation
The GoodID SDK requires the [Microsoft .NET Core 2.2](https://dotnet.microsoft.com/download/dotnet-core/2.2)  framework or any compatible version.
To install the framework, please follow the instruction on the linked site.

If the installation was successfully, the next command should show you the version of the installed framework.
```
ubuntu@ubuntu-xenial:~/dotnet-sdk$ dotnet --version
2.2.104
```
The next step is obtaining the source code of the GoodID SDK.
The source should containing the following projects:
- **GoodId.Core**: This is the GoodId SDK. This library is responsible for constructing a GoodId request and also responsible for validating and fetching the response from GoodID's server
- **GoodId.CoreTests**: It contains the test of the GoodId SDK. It's using NUnit  testing framework. _It is an incomplete state at the moment._

The GoodID SDK has some dependency on 3rd party libs. To resolve them, you have to run the following command from the solution's root directory: 
```$xslt
dotnet restore
```

If all the requirements are met, you can build the project from its source The example is using the Release configuration For more configuration and switches please visit  the [dotnet cli](https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet?tabs=netcore22) documentation.
```
dotnet build -c Release 
```
The command has created a `dotnetcoreapp2.2` directory in the bin folder of all of the project folders, which contains the built DLLs.

## Running the application
**IMPORTANT**: THIS SECTION IS OUTDATED. YOU CAN FIND [HERE](https://github.com/idandtrust/goodid-dotnet-sdk-demo/) THE EXAMPLE PROJECT

After a successful build you can run the application. **IMPORTANT:** The application needs to be configured to work properly. see [Configuring the application](#head-configuring-the-application) section .

Run the demo application! (GoodIdMvcDemoSite)
``` 
 dotnet ./build/dotnetcoreapp2.2/GoodIdMvcDemoSite.dll
```
You should see similar output:
 ``` 
 ubuntu@ubuntu-xenial:~/dotnet-sdk/GoodIdMvcDemoSite$ dotnet ./build/dotnetcoreapp2.2/GoodIdMvcDemoSite.dll
 info: Microsoft.AspNetCore.DataProtection.KeyManagement.XmlKeyManager[0]
       User profile is available. Using '/home/ubuntu/.aspnet/DataProtection-Keys' as key repository; keys will not be encrypted at rest.
 Hosting environment: Production
 Content root path: /home/ubuntu/dotnet-sdk/GoodIdMvcDemoSite$
 Now listening on: http://127.0.0.1:5001
 Application started. Press Ctrl+C to shut down.
 ```
### <a name="head-configuring-the-application"></a>Configuring the application
You can configure the application through modifying the `appsettings.json` and `appsettings.{ASPNETCORE_ENVIRONMENT}.json`files. The environment specific config file overwrites the default config file.

You have multiple possibilities to set this `ASPNETCORE_ENVIRONMENT` value (for example to Development value):

- If you’re using PowerShell in Windows, execute $Env:ASPNETCORE_ENVIRONMENT = "Development"
- If you’re using cmd.exe in Windows, execute setx ASPNETCORE_ENVIRONMENT "Development", and then restart your command prompt to make the change take effect
- If you’re using Mac/Linux, execute export ASPNETCORE_ENVIRONMENT=Development

**IMPORTANT:** The default location of this file is the directory where you started the `dotenv` program.

An example configuration file looks like this:
```json
{
  "Kestrel": {
    "EndPoints": {
      "Http": {
        "Url": "http://127.0.0.1:5001/"
      }
    }
  },

  "Logging": {
    "IncludeScopes": false,
    "LogLevel": {
      "Default": "Warning"
    }
  },
  
  "GoodId": {
    "ClientId": "YOUR GOODID CLIENT ID",
    "ClientSecret": "YOUR GOODID SECRET",
    "RedirectUri": "YOUR LOGIN ENDPOINT",
    "SigPrivKeyPem": "YOUR PRIVATE SIGNING RSA KEY IN PEM FORMAT",
    "EncPrivKeyPem": "YOUR PRIVATE ENCRYPTION RSA KEY IN PEM FORMAT"
  }
}
```
#### Kestrel section
Kestrel is a cross-platform web server for ASP.NET Core. 
The `EndPoints.Http.Url` value tells the initial IP address and Port number, where the webserver is listening. 

**IMPORTANT:** If you are using a proxy before the Kestrel, leave the IP address on the loopback address (127.0.0.1)

For more configuration possibilities, please read the [Microsoft documentation](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel?view=aspnetcore-2.2)
#### Logging section
Responsible for logs appearing in the console.
For the LogLevel values. please  [visit the Microsoft documentation](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.logging.loglevel?view=aspnetcore-2.2)

#### GoodID section
You can specify the GoodID relevant values, required by the GoodID SDK.
- **ClientId:** This is your identifier toward the GoodID, given at the registration.
- **ClientSecret:** This is your secret using when communicating with the GoodID. This is also received during the registration.
- **RedirectUri:** This URL belongs to your application; GoodID sends the data to this route.
- **SigPrivKeyPem:** Your signing private RSA key in PEM format (Begins with `-----BEGIN RSA PRIVATE KEY-----` It can not contains any line breaks)
- **EncPrivKeyPem:** Your private RSA key in PEM format used for encryption (Begins with `-----BEGIN RSA PRIVATE KEY-----` It can not contains any line breaks)


### Reverse proxy server configuration
Sometimes, you may want to use a reverse proxy server before the application. In this case please visit and follow 
[this Microsoft tutorial.](https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/linux-apache?view=aspnetcore-2.2)
