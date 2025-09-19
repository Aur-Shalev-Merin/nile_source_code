# Nile Shopping Website

This is the source code for the Nile shopping website.

## Running the Code
This website is written in Python using the Flask framework. To run it:

1. Install Python from https://www.python.org/.
2. Install Flask using the command `python -m pip install flask`.
3. Run the server with the command `python app.py`.
4. View the website by visiting http://localhost:8000.

The Flask app is configured to run with `debug=true`, meaning it will automatically reload any time the code is modified. If you disable this, you will have to manually restart the server every time you make a change. Additionally, users, products, and purchases are stored in-memory, so restarting the server will reset them back to the original defaults.

## Modifying the Code
This folder contains the following code files:

- app.py: The web server code. This is the only file you need to modify.
- templates/: The HTML templates served by app.py. You do not need to modify these, but they can help your understanding of how the website operates. These are written using Flask's template system, which allows Flask to insert variables and add additional logic to change how the page is rendered: for more information, see the documentation here: https://flask.palletsprojects.com/en/3.0.x/tutorial/templates/.
- static/: Static assets, like images and CSS files. These are purely aesthetic, and do not matter for the lab.

All of the important code is in `app.py`. This file is annotated with comments explaining what each section of code does. If you have any questions, you are welcome to ask the "Nile Engineers" (the teaching team) who are happy to explain how their code works.