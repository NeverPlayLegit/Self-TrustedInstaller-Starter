# Self-TrustedInstaller-Starter
An application that starts itself as trusted installer if started with administration privileges

![](demo.gif)

Flow:
  1. Application starts and checks for admin privileges
  2. If no admin privileges are present restart self with admin privileges
  3. Install and start self as service ("--service" parameter")
  4. Application as service starts a new instance of itself with winlogon token copy and then deletes the service
  5. Application is now running as trusted installer
