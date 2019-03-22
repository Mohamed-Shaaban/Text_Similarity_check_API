From python:3
WORKDIR /user/src/app
COPY requirement.txt ./
RUN pip install --no-cache-dir -r requirement.txt
COPY . .
RUN pip install ./spaCy-2.1.1.tar.gz
CMD ["python","app.py"]
