ARG python_version=3.14
ARG debian_version=slim-trixie

FROM python:${python_version}-${debian_version}

# repeat without defaults in this build-stage
ARG python_version
ARG debian_version

# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

RUN apt update && \
    apt -y full-upgrade && \
    apt -y install htop procps iputils-ping locales vim tini bind9-dnsutils ipset git libolm-dev && \
    pip install --upgrade pip && \
    rm -rf /var/lib/apt/lists/*

RUN sed -i -e 's/# de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen && \
    update-locale LC_ALL=de_DE.UTF-8 LANG=de_DE.UTF-8 && \
    rm -f /etc/localtime && \
    ln -s /usr/share/zoneinfo/Europe/Berlin /etc/localtime


# MULTIARCH-BUILD-INFO: https://itnext.io/building-multi-cpu-architecture-docker-images-for-arm-and-x86-1-the-basics-2fa97869a99b
ARG TARGETOS
ARG TARGETARCH
RUN echo "I'm building for $TARGETOS/$TARGETARCH"

# default UID and GID are the ones used for selenium in seleniarm/standalone-chromium:107.0

ARG UID=1200
ARG GID=1201
ARG UNAME=pythonuser
RUN groupadd -g ${GID} -o ${UNAME} && \
    useradd -m -u ${UID} -g ${GID} -o -s /bin/bash ${UNAME}

USER ${UNAME}

ENV PATH="/home/pythonuser/.local/bin:$PATH"

WORKDIR /app

COPY --chown=${UID}:${GID} requirements.txt ./
RUN pip3 install --no-cache-dir --upgrade -r ./requirements.txt

# ADD --chown=${UID}:${GID} "https://www.random.org/cgi-bin/randbyte?nbytes=10&format=h" skipcache

COPY --chown=${UID}:${GID} README.md pyproject.toml ./

COPY --chown=${UID}:${GID} openclaw_k8s_toggle_operator ./openclaw_k8s_toggle_operator
RUN pip install --no-cache-dir .


# RUN rm skipcache

# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

#ENV PYTHONPATH=${PYTHONPATH:+${PYTHONPATH}:}/app:/app/mqttstuff
ENV PYTHONPATH=/app

ARG gh_ref=gh_ref_is_undefined
ENV GITHUB_REF=$gh_ref
ARG gh_sha=gh_sha_is_undefined
ENV GITHUB_SHA=$gh_sha
ARG buildtime=buildtime_is_undefined
ENV BUILDTIME=$buildtime


# ENTRYPOINT ["openclaw-k8s-toggle-operator"]

ENTRYPOINT ["tini", "--"]
CMD ["openclaw-k8s-toggle-operator"]
