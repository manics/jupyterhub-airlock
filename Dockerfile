FROM docker.io/library/python:3.13.0-slim-bookworm

RUN apt-get update -y -q && \
    apt-get install -y -q --no-install-recommends \
        git && \
    rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1000 jovyan

COPY jupyterhub_airlock /src/jupyterhub_airlock
COPY LICENSE.txt pyproject.toml requirements.in requirements.txt /src/

# Override this with a build-arg so that we don't need to copy .git
ARG SETUPTOOLS_SCM_PRETEND_VERSION_FOR_JUPYTERHUB_AIRLOCK=0.0.0
# COPY .git /src/.git
RUN pip install --no-cache-dir -r /src/requirements.txt /src
RUN pip install /src

USER jovyan

VOLUME [ "/egress" ]
# Must be externally provided:
# VOLUME [ "/users" ]
EXPOSE 8041
ENTRYPOINT ["jupyterhub-airlock"]
CMD ["--filestore=/egress", "--userstore=/users"]
