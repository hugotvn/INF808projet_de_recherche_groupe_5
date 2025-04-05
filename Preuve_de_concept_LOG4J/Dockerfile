FROM tomcat:8.0.36-jre8

RUN rm -rf /usr/local/tomcat/webapps/*
ADD target/log4shell-1.0-SNAPSHOT.war /usr/local/tomcat/webapps/ROOT.war
COPY ConfTomcat/logging.properties ConfTomcat/server.xml /usr/local/tomcat/conf

EXPOSE 8080 
CMD ["catalina.sh", "run"]
