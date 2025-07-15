import json
from jinja2 import Environment, FileSystemLoader

def generate_report(results, formats=['json']):
    if 'json' in formats:
        with open("report.json", "w") as f:
            json.dump(results, f, indent=4)
    if 'html' in formats:
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report.html.jinja')
        html_output = template.render(results=results)
        with open("report.html", "w") as f:
            f.write(html_output)
    print("Reports generated.")
