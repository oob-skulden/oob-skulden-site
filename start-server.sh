#!/bin/bash
VM_IP=$(hostname -I | awk '{print $1}')
echo "Starting Hugo server..."
echo "Access at: http://${VM_IP}:1313"
hugo server -D --bind 0.0.0.0 --baseURL "http://${VM_IP}:1313"
