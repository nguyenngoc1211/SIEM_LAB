FROM bkimminich/juice-shop:latest

WORKDIR /soc
COPY backend.js healthcheck.js fixtures/ /soc/

EXPOSE 3001
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["/soc/backend.js"]
