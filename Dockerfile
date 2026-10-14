FROM python:3.12-slim AS runtime

ARG ATTACK_CORE_REF
RUN test -n "$ATTACK_CORE_REF" || (echo "ATTACK_CORE_REF must be an immutable attack-v19-core commit or tag" >&2; exit 2)

WORKDIR /app
COPY pyproject.toml ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
      "attack-v19-core @ https://github.com/poojakira/attack-v19-core/archive/$ATTACK_CORE_REF.zip"

# Install all declared runtime dependencies from the canonical manifest, except
# the already-installed immutable core archive, without needing Git in this image.
RUN python -c "import tomllib; from pathlib import Path; deps=tomllib.loads(Path('pyproject.toml').read_text())['project']['dependencies']; Path('/tmp/runtime-deps.txt').write_text(chr(10).join(d for d in deps if not d.startswith('attack-v19-core @')))" \
    && python -m pip install --no-cache-dir -r /tmp/runtime-deps.txt

COPY . /app
RUN python -m pip install --no-cache-dir --no-deps .

RUN useradd --create-home --uid 10001 detector
USER detector

ENTRYPOINT ["attack-detect"]
CMD ["--input", "-", "--output", "-"]
