# Task 4: Docker chỉ build C++ Standard Library, không dùng thư viện crypto ngoài.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake g++ make && rm -rf /var/lib/apt/lists/*
WORKDIR /code
COPY . .
RUN cmake -S . -B /work/build -DCMAKE_BUILD_TYPE=Release -DAES_LIBRARY_TYPE=BOTH -DAES_ENABLE_JNI=OFF \
 && cmake --build /work/build --parallel 2 \
 && ctest --test-dir /work/build --output-on-failure

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=build /work/build/aes_tests /usr/local/bin/aes_tests
CMD ["/usr/local/bin/aes_tests"]
