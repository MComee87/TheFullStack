
   The Full Stack

The blog is written in python, html, css and using twitter's bootstrap and delpoyed with Google's App Engine.

   Instructions
download the google sdk for python  (https://cloud.google.com/appengine/downloads)

Clone from github

```
git clone https://github.com/MComee87/TheFullStack
```

```
cd TheFullStack
```

run dev_appserver.py .

This will render a local version of the site. To access the site: https://localhost:8080.

To check the instance: https://localhost:8000


run gcloud app deploy app.yaml --project [YOUR GAE PROJECT NAME]

This will deploy your blog live to appspot.com. To access the site: https://[YOUR GAE PROJECT NAME].appspot.com
