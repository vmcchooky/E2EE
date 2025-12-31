from typing import Generic, TypeVar, Optional
from pydantic import BaseModel, Field

T = TypeVar('T')


class BaseResponse(BaseModel, Generic[T]):
    """Base response schema for all API responses."""
    status_code: int = Field(..., description="HTTP status code phản hồi")
    success: bool = Field(..., description="Trạng thái thành công hay thất bại")
    message: str = Field(..., description="Thông báo")
    data: Optional[T] = Field(default=None, description="Dữ liệu trả về")


class SuccessResponse(BaseResponse[T]):
    """Response schema for successful operations."""
    status_code: int = Field(default=200, description="HTTP status code phản hồi")
    success: bool = Field(default=True, description="Luôn là True")
    message: str = Field(default="Thành công", description="Thông báo mặc định")


class ErrorResponse(BaseResponse[None]):
    """Response schema for error responses."""
    status_code: int = Field(default=400, description="HTTP status code phản hồi")
    success: bool = Field(default=False, description="Luôn là False")
    data: None = Field(default=None, description="Không có data khi lỗi")


# Helper functions để tạo response dễ dàng
def success_response(data: T = None, message: str = "Thành công", status_code: int = 200) -> dict:
    """Helper function to create a success response."""
    return {
        "status_code": status_code,
        "success": True,
        "message": message,
        "data": data
    }


def error_response(message: str = "Có lỗi xảy ra", status_code: int = 400) -> dict:
    """Helper function to create an error response."""
    return {
        "status_code": status_code,
        "success": False,
        "message": message,
        "data": None
    }

