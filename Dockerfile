FROM ubuntu:latest
WORKDIR /root
ENV PATH=/root/.local/bin:$PATH
RUN apt update && apt install -y git vim curl htop net-tools python3 python-is-python3 libmagic1 && curl vim.kelvinho.org | bash && curl -Ls https://astral.sh/uv/install.sh | bash
RUN uv venv env1 && echo "\nsource /root/.bashenv\n" >> /root/.bashrc && cat <<EOF >/root/.bashenv
    export PATH="$PATH:/root/.local/bin"; . /root/env1/bin/activate
    function help() { echo ""; echo "Commands: ";
        echo "- run: run the application, with auto reloading on file change"
        echo "- runG: run the application using gunicorn with 2 workers, with auto reloading on file change"
        echo "- runOld: run the application, while loop with bare python, does not auto reload, worst case scenario running"
        echo "- kill: kills the running application"
        echo "- update: updates the k1lib and aigu libraries"; echo ""; }
    function run() { watchfiles --filter python --sigint-timeout 2 'python main.py'; }
    function runG() { local workers=\${1:-4}; watchfiles --filter python 'pkill -HUP gunicorn' &
        sleep 2; gunicorn -k gthread -w \$workers --threads 8 -b 0.0.0.0:80 --graceful-timeout 5 main:app; }
    function runOld() { while true; do python main.py >/dev/null 2>&1; done; }
    function kill() { pkill -9 -f watchfiles; pkill -9 -f gunicorn; pkill -9 -f python; pkill -9 -f python3; }
    function update() { uv pip install --force-reinstall --extra-index-url https://pypi.aigu.vn k1lib; }
EOF
RUN . /root/env1/bin/activate && uv pip install watchfiles flask psycopg2-binary requests unidecode pycryptodome bcrypt python-magic gunicorn
RUN bash -c ". /root/.bashenv && update"
RUN . /root/env1/bin/activate && uv pip install MarkupSafe mpld3 numpy pandas matplotlib scipy scikit-learn beautifulsoup4 jinja2 pytest pillow opencv-python nltk spacy sympy
WORKDIR /code
CMD ["./startup"]


