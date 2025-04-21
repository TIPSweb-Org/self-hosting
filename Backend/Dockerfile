FROM ghcr.io/selkies-project/nvidia-egl-desktop:latest

USER root

# Install dependencies needed for building SOFA
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libboost-all-dev \
    libcgal-dev \
    libeigen3-dev \
    libpng-dev \
    libtinyxml-dev \
    libtinyxml2-dev \
    libxml2-dev \
    python3-dev \
    python3-numpy \
    qtbase5-dev \
    qtchooser \
    qt5-qmake \
    libqt5opengl5-dev \
    libqt5charts5-dev \
    libglew-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the SOFA TIPS repository
RUN git clone https://bitbucket.org/surflab/sofa_tips.git /home/ubuntu/sofa_tips

# Create build directory
WORKDIR /home/ubuntu/sofa_tips
RUN mkdir -p build

# Build SOFA TIPS
WORKDIR /home/ubuntu/sofa_tips/build
RUN cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Create a startup script
RUN echo '#!/bin/bash\ncd /home/ubuntu/sofa_tips/build/bin\n./runSofa "$@"' > /usr/local/bin/start-sofa \
    && chmod +x /usr/local/bin/start-sofa

# Create autostart directory and file
RUN mkdir -p /home/ubuntu/.config/autostart && \
    echo "[Desktop Entry]\nType=Application\nExec=/usr/local/bin/start-sofa\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true\nName=SOFA TIPS\nComment=Start SOFA TIPS automatically" > /home/ubuntu/.config/autostart/sofa-tips.desktop && \
    chmod +x /home/ubuntu/.config/autostart/sofa-tips.desktop && \
    chown -R ubuntu:ubuntu /home/ubuntu/.config

# Set permissions
RUN chown -R ubuntu:ubuntu /home/ubuntu/sofa_tips
RUN chmod -R 755 /home/ubuntu/sofa_tips

# Switch back to the ubuntu user for interactive sessions
USER ubuntu
WORKDIR /home/ubuntu