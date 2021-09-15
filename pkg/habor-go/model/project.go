package model

type Project struct {
	UpdateTime   string `json:"update_time"`
	OwnerName    string `json:"owner_name"`
	Name         string `json:"name"`
	Deleted      bool   `json:"deleted"`
	OwnerId      int    `json:"owner_id"`
	RepoCount    int    `json:"repo_count"`
	ChartCount   int    `json:"chart_count"`
	CreationTime string `json:"creation_time"`
	//Togglable         bool   `json:"togglable"`
	CurrentUserRoleId int `json:"current_user_role_id"`
	ProjectId         int `json:"project_id"`
	RegistryId        int `json:"registry_id"`
}
