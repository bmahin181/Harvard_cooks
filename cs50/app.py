import os
import re
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from jinja2 import Template

from helpers import apology, login_required, usd

# Configure application
app = Flask(__name__)

# Custom filter for currency formatting
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.urandom(24)  # Add a strong secret key to sign session cookies.
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///recipe_hub.db")


# Middleware to prevent caching of responses
@app.after_request
def after_request(response):
    """Ensure responses aren't cached."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Main route with unified database queries
@app.route("/")
@login_required
def index():
    """Show all recipes."""

    # Fetch all recipes with author information and comment count in a single query
    recipes = db.execute("""
        SELECT 
            r.*, 
            u.username AS author,
            COUNT(DISTINCT c.id) AS comment_count
        FROM recipes r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN comments c ON r.id = c.recipe_id
        GROUP BY r.id
        ORDER BY r.created_at DESC
    """)

    for recipe in recipes:
        # Split ingredients and instructions into lists
        recipe["ingredients"] = recipe["ingredients"].split(" | ")  # Adjust separator if needed
        recipe["steps"] = recipe["instructions"].split(" | ")

        # Fetch comments for each recipe
        recipe["comments"] = db.execute("""
            SELECT c.comment_text, u.username 
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.recipe_id = :recipe_id
        """, recipe_id=recipe["id"])

    return render_template("index.html", recipes=recipes)



# Login route: Allows users to log in to their account
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Query the database for the user
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        
        # Validate user credentials
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password", 403)
            
        # Check if email is verified
        if not rows[0]["is_verified"]:
            flash("Please verify your email before logging in. Check your inbox for the verification link.", "warning")
            return redirect(url_for("login"))
        
        # Store user information in the session
        session["user_id"] = rows[0]["id"]  # Store user ID
        session["user_name"] = rows[0]["username"]  # Store username for easier access

        # Redirect to the homepage after login
        return redirect("/")
        
    return render_template("login.html")


# Logout route: Logs the user out of their session
@app.route("/logout")
def logout():
    """Log user out."""
    session.clear()
    return redirect("/")

# Register route: Allows new users to register
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user."""
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check for complete form submission
        if not username or not email or not password or password != confirmation:
            return apology("invalid input or passwords do not match", 400)

        # Validate Harvard email
        harvard_domains = ("@harvard.edu", "@college.harvard.edu")
        if not email.lower().endswith(harvard_domains):
            return apology("please use a valid Harvard email address (@harvard.edu or @college.harvard.edu)", 400)

        try:
            # Insert user with verified status directly (set is_verified to True)
            db.execute(
                "INSERT INTO users (username, email, hash, is_verified) VALUES (?, ?, ?, ?)",
                username,
                email.lower(),
                generate_password_hash(password),
                True  # Set is_verified to True
            )

            flash("Registration successful!", "success")
            return redirect(url_for("login"))

        except ValueError:
            return apology("username already exists", 400)

    return render_template("register.html")

# Change password route: Allows users to change their password
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow users to change their password."""
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not old_password or not new_password or new_password != confirmation:
            return apology("invalid input or passwords do not match", 400)

        # Check old password
        user_id = session["user_id"]
        rows = db.execute("SELECT hash FROM users WHERE id = ?", user_id)

        if not check_password_hash(rows[0]["hash"], old_password):
            return apology("invalid old password", 400)

        # Update password
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            generate_password_hash(new_password),
            user_id,
        )
        return redirect("/")

    return render_template("change_password.html")

@app.route("/recipes", methods=["GET", "POST"])
@login_required
def recipes_form():
    """Display the recipes added by the current user and allow adding a new one."""
    
    if request.method == "POST":
        name = request.form['name']
        ingredients = request.form.getlist('ingredient[]')
        quantities = request.form.getlist('quantity[]')
        steps = request.form.getlist('step[]')

        if not ingredients or not steps:
            return apology("Must provide ingredients and steps.", 400)

        if len(ingredients) != len(quantities):
            return apology("The number of ingredients and quantities don't match.", 400)

        ingredients_combined = ', '.join([f"{ingredient} ({quantity})" for ingredient, quantity in zip(ingredients, quantities)])
        steps_combined = ' | '.join(steps)

        user_id = session.get("user_id")

        db.execute(
            "INSERT INTO recipes (recipe_name, ingredients, instructions, user_id) VALUES (?, ?, ?, ?)",
            name, ingredients_combined, steps_combined, user_id
        )

        return redirect(url_for('recipes_form'))

    # Fetch only the user's own recipes
    user_id = session.get("user_id")
    recipes = db.execute("SELECT id, recipe_name, ingredients, instructions FROM recipes WHERE user_id = ?", user_id)

    for recipe in recipes:
        recipe["steps"] = recipe["instructions"].split(" | ")

    return render_template("recipes.html", recipes=recipes)


@app.route("/edit_recipe/<int:recipe_id>", methods=["GET", "POST"])
@login_required
def edit_recipe(recipe_id):
    """Edit an existing recipe."""
    
    # Get the recipe from the database
    recipe = db.execute("SELECT * FROM recipes WHERE id = ?", recipe_id)
    
    if not recipe:
        return apology("Recipe not found", 404)
    
    recipe = recipe[0]
    # Split the ingredients and steps into lists
    ingredients = recipe["ingredients"].split(", ")
    quantities = [ingredient.split(" (")[1][:-1] for ingredient in ingredients]
    ingredients = [ingredient.split(" (")[0] for ingredient in ingredients]
    steps = recipe["instructions"].split(" | ")

    if request.method == "POST":
        name = request.form['name']
        ingredients = request.form.getlist('ingredient[]')
        quantities = request.form.getlist('quantity[]')
        steps = request.form.getlist('step[]')

        if not ingredients or not steps:
            return apology("Must provide ingredients and steps.", 400)

        if len(ingredients) != len(quantities):
            return apology("The number of ingredients and quantities don't match.", 400)

        ingredients_combined = ', '.join([f"{ingredient} ({quantity})" for ingredient, quantity in zip(ingredients, quantities)])
        steps_combined = ' | '.join(steps)

        db.execute(
            "UPDATE recipes SET recipe_name = ?, ingredients = ?, instructions = ? WHERE id = ?",
            name, ingredients_combined, steps_combined, recipe_id
        )

        return redirect(url_for("recipes_form"))

    # Pass the data to the template for prepopulation
    return render_template("edit_recipe.html", recipe=recipe, ingredients=ingredients, quantities=quantities, steps=steps)


@app.route("/delete_recipe", methods=["POST"])
@login_required
def delete_recipe():
    recipe_id = request.form.get("recipe_id")
    
    if recipe_id:
        # Delete the recipe from the database
        db.execute("DELETE FROM recipes WHERE id = :recipe_id", recipe_id=recipe_id)
    
    # After deletion, redirect to the recipes page
    return redirect(url_for("recipes_form"))


@app.route("/add_comment/<int:recipe_id>", methods=["POST"])
@login_required
def add_comment(recipe_id):
    comment_text = request.form.get("comment_text")
    if not comment_text:
        flash("Comment cannot be empty.", "danger")
        return redirect("/")

    user_id = session.get("user_id")
    if not user_id:
        return redirect("/login")

    user_name = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]

    db.execute("""
        INSERT INTO comments (recipe_id, user_id, comment_text)
        VALUES (?, ?, ?)
    """, recipe_id, user_id, comment_text)

    flash("Comment added successfully!", "success")
    return redirect("/")


@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    """Delete a comment."""
    # Check if the comment exists and belongs to the current user
    comment = db.execute("SELECT * FROM comments WHERE id = ?", comment_id)

    if not comment:
        return apology("Comment not found", 404)

    # Restrict deletion to the comment's owner or admin (if applicable)
    if comment[0]["user_id"] != session["user_id"]:
        return apology("You are not authorized to delete this comment", 403)

    # Delete the comment
    db.execute("DELETE FROM comments WHERE id = ?", comment_id)
    flash("Comment deleted successfully.", "success")
    return redirect(request.referrer or "/")


@app.template_filter('zip')
def zip_filter(list1, list2):
    return zip(list1, list2)
