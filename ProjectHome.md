This project is a complete Google App Engine example application for the [FriendFeed API v2](http://friendfeed.com/api/documentation). You can see this project in action at [http://friendfeed-api.appspot.com/](http://friendfeed-api.appspot.com/).

For more information about the FriendFeed API:

  * [FriendFeed API v2 documentaion](http://friendfeed.com/api/documentation)
  * [FriendFeed API libraries](http://code.google.com/p/friendfeed-api/)

How to run the example on your desktop computer:

  1. [Setup the App Engine development environment](http://code.google.com/appengine/docs/python/gettingstarted/devenvironment.html)
  1. [Checkout the source for the example](http://code.google.com/p/friendfeed-api-example/source/checkout)
  1. [Register your application at FriendFeed](http://friendfeed.com/api/applications).  Set the callback URL to http://localhost:8080/oauth/callback
  1. Edit the file application.py in the source directory.  Change the values in the FRIENDFEED\_API\_TOKEN dictionary to the consumer key and consumer secret from your application registration.
  1. From the root of the application source directory, run the App Engine command "dev\_appserver.py .". Note that there's a period at the end of the command.
  1. View the application in the browser at http://localhost:8080/