from fastapi import FastAPI, Request
from predict import predict
import json
import urllib.parse
import pandas as pd
import uvicorn
import os
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse



app = FastAPI(debug=True)


def process(zeek_df):


    output = predict(pd.DataFrame(zeek_df))




    return str(output)

def generate_response(json_data, output):
    return {
        "input": str(json_data),
        "output": str(output),
    }



@app.get("/")
async def root():
    return {"message": "Detect Vulnerabilities from http log"}

@app.post("/predict")
async def predict_review(data: Request):
    json_data = await data.json()

    detection = process(json_data)
    return detection

    # return generate_response(json_data, detection)


@app.get("/status")
async def status():
    return {"status": "OK"}


if __name__ == "__main__":
    uvicorn.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))