"""
Autoencoder module for KitNET anomaly detection.
Uses PyTorch for numerical stability, rapid CPU/GPU tensor operations, and gradient optimization.
"""
from typing import Tuple
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np


class KitAutoencoder(nn.Module):
    """
    Single-layer Bottleneck Autoencoder for KitNET ensemble.
    Architecture: Input (d) -> Bottleneck (k) -> Output (d).
    Uses LeakyReLU in bottleneck and Linear reconstruction.
    """
    def __init__(self, input_dim: int, hidden_ratio: float = 0.75, lr: float = 0.05):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = max(1, int(np.ceil(input_dim * hidden_ratio)))

        self.encoder = nn.Sequential(
            nn.Linear(self.input_dim, self.hidden_dim),
            nn.LeakyReLU(negative_slope=0.1)
        )
        self.decoder = nn.Sequential(
            nn.Linear(self.hidden_dim, self.input_dim)
        )

        self.optimizer = optim.Adam(self.parameters(), lr=lr, weight_decay=1e-5)
        self.loss_fn = nn.MSELoss(reduction='none')

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        code = self.encoder(x)
        reconstruction = self.decoder(code)
        return reconstruction

    def train_step(self, x: np.ndarray) -> Tuple[float, np.ndarray]:
        """
        Executes one training step on an input vector or mini-batch.
        Returns: (scalar RMSE, per-feature squared error array).
        """
        self.train()
        tensor_x = torch.from_numpy(x).float()
        if tensor_x.ndim == 1:
            tensor_x = tensor_x.unsqueeze(0)

        self.optimizer.zero_grad()
        recon = self.forward(tensor_x)
        per_elem_se = (tensor_x - recon) ** 2
        loss = per_elem_se.mean()
        loss.backward()
        self.optimizer.step()

        rmse = torch.sqrt(loss).item()
        se_features = per_elem_se.detach().cpu().numpy().squeeze()
        return rmse, se_features

    def evaluate(self, x: np.ndarray) -> Tuple[float, np.ndarray]:
        """
        Inference mode: evaluates reconstruction error without updating weights.
        Returns: (scalar RMSE, per-feature squared error array).
        """
        self.eval()
        with torch.no_grad():
            tensor_x = torch.from_numpy(x).float()
            if tensor_x.ndim == 1:
                tensor_x = tensor_x.unsqueeze(0)
            recon = self.forward(tensor_x)
            per_elem_se = (tensor_x - recon) ** 2
            rmse = torch.sqrt(per_elem_se.mean()).item()
            se_features = per_elem_se.cpu().numpy().squeeze()
            return rmse, se_features
