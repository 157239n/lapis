FROM ubuntu:latest
WORKDIR /root
ENV PATH=/root/.local/bin:$PATH
RUN apt update && apt install -y git vim curl htop net-tools python3 python-is-python3 libmagic1 && curl vim.kelvinho.org | bash && curl -Ls https://astral.sh/uv/install.sh | bash
RUN apt update && apt install -y wget zip unzip bzip2 7zip sqlite3 jq csvkit xmlstarlet zstd pigz parallel gnuplot graphviz file
RUN apt update && apt install -y r-base r-base-dev octave octave-statistics build-essential gcc g++ make cmake gdb rustc cargo golang openjdk-21-jdk maven
RUN apt update && apt install -y seqkit openbabel hmmer ncbi-blast+ mmseqs2 samtools bcftools bedtools tabix
RUN apt update && apt install -y nginx
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && apt-get install -y nodejs
RUN uv venv env1 && echo "\nsource /root/.bashenv\n" >> /root/.bashrc && cat <<EOF >/root/.bashenv
    export PATH="$PATH:/root/.local/bin"; . /root/env1/bin/activate
    function update() { uv pip install --force-reinstall --extra-index-url https://pypi.aigu.vn k1lib; }
EOF
RUN . /root/env1/bin/activate && uv pip install watchfiles flask psycopg2-binary requests unidecode pycryptodome bcrypt python-magic gunicorn
RUN bash -c ". /root/.bashenv && update" && echo 1
RUN . /root/env1/bin/activate && uv pip install MarkupSafe mpld3 numpy pandas matplotlib scipy scikit-learn beautifulsoup4 jinja2 pytest pillow opencv-python nltk spacy sympy
RUN . /root/env1/bin/activate && uv pip install rdkit biopython pyarrow pymatgen playwright duckdb cryptography psutil && uv run playwright install chromium
RUN cat <<EOF >>/root/.bashenv
    function help() { echo ""; echo "Commands: ";
        echo "- run: run the application, with auto reloading on file change"
        echo "- runG: run the application using gunicorn with 2 workers, with auto reloading on file change"
        echo "- runOld: run the application, while loop with bare python, does not auto reload, worst case scenario running"
        echo "- kill: kills the running application"
        echo "- update: updates the k1lib and aigu libraries"; echo ""; }
    function run1() { watchfiles --filter python --sigint-timeout 2 'python -u lapis.py' &
        python -u radon.py -pk 8636175bcfeb963cf8619019a8e3c089a6d82662e28f514e068ff0b5d62ad5c3 & }
    function run2() { python -u radon.py -pk 1a0c59457271e8a63e2ed48e900f99a03e477ec75998fc241ed4317e0aae1512 -sc /central.conf --dashboard & }
    function runG() { local workers=\${1:-4}; watchfiles --filter python 'pkill -HUP gunicorn' &
        sleep 2; gunicorn -k gthread -w \$workers --threads 8 -b 0.0.0.0:80 --graceful-timeout 5 lapis:app; }
    function runOld() { while true; do python main.py >/dev/null 2>&1; done; }
    function kill() { pkill -9 -f watchfiles; pkill -9 -f gunicorn; pkill -9 -f python; pkill -9 -f python3; }
EOF
WORKDIR /code


