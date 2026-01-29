### Automated SQL injection Tool
SQLMap is an automated tool for detecting and exploiting SQL injection vulnerabilities in web applications

As this is a command-line tool, you must open your Linux OS terminal to use it. The `--help` command with SQLMap will list all the available flags you can use. If you don't want to manually add the flags to each command, use the `--wizard` flag with SQLMap.

The `--dbs` flag helps you to extract all the database names.

this can extract information about the tables of that database by using `-D database_name --tables`

After obtaining the tables, if you want to enumerate the records in those tables, you can use `-D database_name -T table_name --dump`.

The first step is to look for a possible vulnerable URL or request. You may often come across some URLs that use GET parameters to retrieve the data. For example, a URL like `http://sqlmaptesting.thm/search?cat=1` uses a parameter `cat` that takes the value `1`. If you see any web application using GET parameters in the URLs to retrieve data, you can test that URL with the -u flag in the SQLMap tool. This is considered to be HTTP GET-based testing. This approach is followed when the application uses GET parameters in the URL to retrieve data from the searches

Now that we have all the available table names of the database, let's dump the records present in the `thomas` table. To do so, we will define the database with the `-D` flag, the table with the `-T` flag, and for extracting the records of the table, we will use the `--dump` flag.

http://10.10.176.12/ai/includes/user_login?email=asdf&password=asdf