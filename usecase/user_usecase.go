package usecase

import (
	"go-rest-api/model"
	"go-rest-api/repository"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

//ユーザーに関する処理をまとめたインターフェース(設計図)を定義している
type IUserUsecase interface {
	SignUp(user model.User) (model.UserResponse, error)
	LogIn(user model.User) (string, error)
}

//userUsecaseという構造体を一度インスタンス化(＝実態を作る)して、それを他の場所(ハンドラーなど)から繰り返し使いまわせるようにするため
type userUsecase struct {
	ur repository.IUserRepository
}

//UserUsecaseを作るための関数であり、依存(repository)を受け取って内部に保持するためのもの
func NewUserUsecase(ur repository.IUserRepository) IUserUsecase {
	return &userUsecase{ur}
}

//新規ユーザーを登録するための処理
//1.パスワードのハッシュ化、2.新しいユーザーをDBに保存する、3.登録されたユーザーを返す
func (uu *userUsecase) SignUp(user model.User) (model.UserResponse, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		return model.UserResponse{}, err
	}

	newUser := model.User{Email: user.Email, Password: string(hash)}
	if err := uu.ur.CreateUser(&newUser); err!=nil {
		return model.UserResponse{}, err
	}

	resUser := model.UserResponse{
		ID:		newUser.ID,
		Email:	newUser.Email,
	}

	return resUser, nil
}

func (uu *userUsecase) LogIn(user model.User) (string, error) {
	storedUser := model.User{}
	if err := uu.ur.GetUserByEmail(&storedUser, user.Email); err != nil {
		return "",err
	}

	err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
	if err != nil {
		return "",err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": storedUser.ID,
		"exp":	   time.Now().Add(time.Hour * 12).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "",err
	}

	return tokenString, nil
}
