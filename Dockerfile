FROM python:3.12-slim AS runtime

ARG ATTACK_CORE_REF
RUN test -n "$ATTACK_CORE_REF" || (echo "ATTACK_CORE_REF must be an immutable attack-v19-core commit or tag" >&2; exit 2)

WORKDIR /app
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
      "attack-v19-core @ https://github.com/poojakira/attack-v19-core/archive/$ATTACK_CORE_REF.zip"

COPY . /app
RUN python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 detector
USER detector

ENTRYPOINT ["attack-detect"]
CMD ["--input", "-", "--output", "-"]
