docker run -d --name func_extract_container-$(openssl rand -hex 8) -v $(pwd)/input_data:/input_data -v $(pwd)/output_data:/output_data -u $(id -u):$(id -g) -itd func_extract
