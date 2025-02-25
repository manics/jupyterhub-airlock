# JupyterHub-airlock toy example

This is a very simple demo of the jupyterhub-airlock component.

It is not secure!

## Example walkthough

### 1. Run JupyterHub

Start a shell in this examples directory. Start JupyterHub, optionally with the `--debug` flag:

```
jupyterhub --debug
```

Open http://localhost:8000 in your browser.

You can use _any_ username and password to login!

The `admin` username is special as it is part of the `egress-admins` group and is responsible for accepting and rejecting egress requests.

### 2. Login as a normal user

Login to JupyterHub as e.g. `user-1` and start your server, you should be taken to JupyterLab.
Create one or more files and optionally directories to be egressed.
In this example the user home filesystem is used as the egress source directory, but in practice this would be a separate filesystem.

Now go to http://localhost:8000/services/airlock/
You can also find that URL through the JupyterHub `Services` dropdown.

You will see a list an empty list of pending, accepted and rejected egress requests.

Click on the `New egress` button, you should see a list of files from your `egress/` directory.

Click the checkboxes for the file(s) you want to egress, then click the `Egress` button.
You should be taken to a summary page for your egress, with status `pending`.

### 3. Login as admin

Go back to http://localhost:8000/ and logout, then login as `admin`.

Now go to http://localhost:8000/services/airlock/
You should see a pending egress request.
Click it.

You will see `accept` and `reject` buttons, pick one.
If you click `accept` th epage should refresh and you will see a download button which will zip up the files and download them.

### 4. Login as a normal user

Go back to http://localhost:8000/ and logout, then login as a normal user, e.g. `user-1`.

Now go to http://localhost:8000/services/airlock/
You should see your original egress request, now under either rejected or accepted.
Click on it.

If it was accepted you will be able to download a zip of your files.
