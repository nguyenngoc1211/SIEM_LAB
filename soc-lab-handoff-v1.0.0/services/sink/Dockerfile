FROM bkimminich/juice-shop:latest

WORKDIR /soc
COPY sink.js /soc/sink.js

EXPOSE 3100
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["/soc/sink.js"]
