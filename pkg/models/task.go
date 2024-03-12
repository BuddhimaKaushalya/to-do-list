package models

import (
	"to-do-list/pkg/config"

	"github.com/jinzhu/gorm"
)

type Task struct {
	gorm.Model
	UserName string `json:"username"` // Foreign key for User
	Name     string `json:"name"`
}

// Initialize the database connection and perform auto-migration
func init() {
	config.Connect()
	db := config.GetDB()
	db.AutoMigrate(&Task{})
}

// creates a new task for the specified user
func CreateTask(task Task) *Task {
	db := config.GetDB()
	db.Create(&task)
	return &task
}

// retrieves all tasks for the specified user
func GetTasks(username string) []Task {
	var tasks []Task
	db := config.GetDB()
	db.Where("user_name = ?", username).Find(&tasks)
	return tasks
}

func UpdateTask(username, taskID string, task Task) *Task {
	db := config.GetDB()
	var existingTask Task
	db.Where("id = ? ", taskID).First(&existingTask)
	if existingTask.ID == 0 {
		return nil
	}
	existingTask.Name = task.Name
	db.Save(&existingTask)
	return &existingTask
}

func DeleteTask(username, taskID string) bool {
	db := config.GetDB()
	var existingTask Task
	db.Where("id = ?", taskID).First(&existingTask)
	if existingTask.ID == 0 {
		return false
	}
	db.Delete(&existingTask)
	return true
}
